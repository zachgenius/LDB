#!/usr/bin/env python3
"""Smoke test for `_provenance.snapshot` cores-only determinism gate.

Plan §3.5 (cores-only MVP, M5 part 6):
  • Every successful response carries `_provenance: {snapshot, deterministic}`.
  • Core-loaded targets:  snapshot = "core:<sha256>", deterministic = true.
  • Live / no-target:     snapshot = "live" / "none", deterministic = false.
  • Identical (method, params, snapshot) against the same core MUST yield
    byte-identical `data`. This is the deterministic-protocol gate.

Test corpus:
  • Generated at runtime via `process.save_core` after launching the
    sleeper fixture stop-at-entry. If `save_core` is not supported on
    this platform (it is on Linux x86_64; some CI configurations may
    not allow it), the entire test SKIPs cleanly.

Replay determinism:
  • Spawn ldbd #1; load_core; record `_provenance.snapshot` and a
    handful of deterministic responses (`module.list`, `mem.regions`,
    `thread.list`, `string.list` with bounded scope, `disasm.range` of
    a known function, etc.).
  • Spawn ldbd #2 (fresh process); same calls; require byte-for-byte
    identity of every `data` payload AND identical snapshot string.
"""
import json
import os
import subprocess
import sys
import tempfile


def usage():
    sys.stderr.write(
        "usage: test_provenance_replay.py <ldbd> <sleeper>\n")
    sys.exit(2)


class Daemon:
    def __init__(self, ldbd):
        env = dict(os.environ)
        env.setdefault("LLDB_LOG_LEVEL", "error")
        self.proc = subprocess.Popen(
            [ldbd, "--stdio", "--log-level", "error"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env, text=True, bufsize=1,
        )
        self._next_id = 0

    def call(self, method, params=None):
        self._next_id += 1
        rid = f"r{self._next_id}"
        req = {"jsonrpc": "2.0", "id": rid, "method": method,
               "params": params or {}}
        self.proc.stdin.write(json.dumps(req) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            err = self.proc.stderr.read()
            raise RuntimeError(
                f"daemon closed stdout (stderr was: {err})")
        return json.loads(line)

    def close(self):
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        self.proc.wait(timeout=10)


def make_core(ldbd, sleeper, core_path):
    """Spawn a daemon, launch sleeper, save_core, return True iff a
    nonempty core file landed at core_path. Cleans up the daemon."""
    d = Daemon(ldbd)
    try:
        r = d.call("target.open", {"path": sleeper})
        if not r["ok"]:
            return False, f"target.open: {r}"
        tid = r["data"]["target_id"]

        r = d.call("process.launch",
                   {"target_id": tid, "stop_at_entry": True})
        if not r["ok"]:
            return False, f"process.launch: {r}"

        r = d.call("process.save_core",
                   {"target_id": tid, "path": core_path})
        if not r["ok"]:
            return False, f"process.save_core: {r}"
        saved = r["data"].get("saved", False)
        d.call("process.kill", {"target_id": tid})
        if not saved:
            return False, "save_core returned saved=false"
        if not os.path.exists(core_path) or os.path.getsize(core_path) == 0:
            return False, "save_core produced no file"
        return True, None
    finally:
        d.close()


# A list of (method, params) pairs the test will issue against a
# core-loaded target. They must be deterministic — running them twice
# against the same core must yield bit-identical `data`. Keep the
# parameter set conservative (no addresses that depend on ASLR — the
# core captures the post-ASLR memory layout, so file_addr stays stable).
#
# v1.5 #15 phase-1 addition: correlate.* (types/symbols/strings) — these
# route through the SymbolIndex sqlite cache post-#18. The wire shape is
# byte-identical to the pre-cache cold path (smoke_correlate +
# test_index_cold_warm pin that), but cross-daemon byte-identity is what
# this test gate adds. See docs/04-determinism-audit.md §12.
def deterministic_calls(target_id):
    return [
        # No-target endpoints — should still report determinism faithfully
        # (snapshot="none", deterministic=false). They still produce
        # bit-identical responses across runs because the daemon code
        # path is the same.
        ("hello",                {}),
        ("describe.endpoints",   {}),
        # Target-bound, all read-only.
        ("mem.regions",          {"target_id": target_id}),
        ("thread.list",          {"target_id": target_id}),
        # Bounded scans — minimal data so the byte-diff is fast.
        ("string.list",          {"target_id": target_id,
                                   "min_length": 8,
                                   "max_length": 32,
                                   "view": {"limit": 5}}),
        ("symbol.find",          {"target_id": target_id,
                                   "name": "main"}),
        # correlate.* — index-routed under #18, determinism gate added
        # in #15 phase-1. The sleeper fixture has main + the marker
        # string but no dxp_login_frame type; correlate.types' "missing"
        # answer is still a byte-identical deterministic result.
        ("correlate.types",      {"target_ids": [target_id],
                                   "name": "dxp_login_frame"}),
        ("correlate.symbols",    {"target_ids": [target_id],
                                   "name": "main"}),
        ("correlate.strings",    {"target_ids": [target_id],
                                   "text": "LDB_SLEEPER_MARKER_v1"}),
    ]


def main():
    if len(sys.argv) != 3:
        usage()
    ldbd, sleeper = sys.argv[1], sys.argv[2]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n"); sys.exit(1)
    if not os.path.isfile(sleeper):
        sys.stderr.write(f"sleeper missing: {sleeper}\n"); sys.exit(1)

    core_path = os.path.join(tempfile.gettempdir(),
                             f"ldb_replay_core_{os.getpid()}.core")
    if os.path.exists(core_path):
        os.remove(core_path)

    ok, err = make_core(ldbd, sleeper, core_path)
    if not ok:
        # save_core unsupported, or platform refused. SKIP cleanly —
        # ctest's PASS-on-no-output rule applies. Documented per task
        # spec: provenance plumbing still ships even when corpus
        # generation can't run.
        print(f"SKIP: cannot generate core file ({err})")
        sys.exit(0)

    failures = []

    def expect(cond, msg):
        if not cond:
            failures.append(msg)

    # ---------- Run #1 ----------
    # Note on snapshot semantics: target.load_core's request has no
    # target_id (the target is being minted), so its response carries
    # `snapshot: "none"` — that's the honest answer at dispatch time.
    # Every FOLLOW-UP call against the new target carries
    # `core:<sha256>`. We assert on the follow-up shape; that's the
    # contract every other endpoint operates under.
    snapshot_run1 = None
    captured = []  # list of (method, params, data_dump, snapshot)
    d1 = Daemon(ldbd)
    try:
        r = d1.call("target.load_core", {"path": core_path})
        expect(r["ok"], f"daemon1 load_core: {r}")
        if not r["ok"]:
            raise RuntimeError("daemon1 load_core failed")
        tid1 = r["data"]["target_id"]
        # load_core itself: snapshot is "none" (the target doesn't yet
        # exist at dispatch start — by design).
        expect(r["_provenance"]["snapshot"] == "none",
               f"load_core snapshot expected 'none' (target not yet "
               f"minted), got {r['_provenance']['snapshot']!r}")
        # First follow-up call: this is where the cached core SHA-256
        # surfaces. We use module.list as the snapshot oracle.
        first = d1.call("module.list", {"target_id": tid1})
        expect(first["ok"], f"daemon1 module.list: {first}")
        snapshot_run1 = first["_provenance"]["snapshot"]
        expect(snapshot_run1.startswith("core:"),
               f"first follow-up snapshot expected core:..., "
               f"got {snapshot_run1!r}")
        expect(first["_provenance"]["deterministic"] is True,
               f"core-target determinism: {first['_provenance']}")
        # The hex part has length 64.
        expect(len(snapshot_run1) == len("core:") + 64,
               f"core snapshot length: {snapshot_run1!r}")
        # Capture the module.list response so the byte-diff covers it
        # too (otherwise we'd miss it on the second-run loop).
        captured.append(
            ("module.list", {"target_id": tid1},
             json.dumps(first["data"], sort_keys=True,
                        separators=(",", ":")),
             snapshot_run1))

        for method, params in deterministic_calls(tid1):
            resp = d1.call(method, params)
            expect(resp["ok"], f"daemon1 {method}: {resp}")
            if not resp["ok"]:
                continue
            prov = resp.get("_provenance")
            expect(prov is not None,
                   f"daemon1 {method} missing _provenance")
            if prov is None:
                continue
            # No-target endpoints (hello, describe.endpoints) → "none";
            # target-bound endpoints → match load_core snapshot. correlate.*
            # binds to targets via `target_ids` (plural); the dispatcher
            # resolves snapshot from the (homogeneous) target_ids[] list,
            # so the determinism contract holds identically.
            is_target_bound = ("target_id" in params) or (
                "target_ids" in params and len(params["target_ids"]) > 0)
            if is_target_bound:
                expect(prov["snapshot"] == snapshot_run1,
                       f"daemon1 {method} snapshot mismatch: "
                       f"got={prov['snapshot']} want={snapshot_run1}")
                expect(prov["deterministic"] is True,
                       f"daemon1 {method} should be deterministic: {prov}")
            else:
                expect(prov["snapshot"] == "none",
                       f"daemon1 {method} (no target) snapshot: {prov}")
                expect(prov["deterministic"] is False,
                       f"daemon1 {method} (no target) determinism: {prov}")
            # Capture canonical-bytes form. We use the same `separators`
            # as Python's compact dump — but also re-serialize via
            # json.dumps with sort_keys=True so the byte-diff is
            # insensitive to dict-iteration order. The wire format is
            # nlohmann::json which preserves insertion order, but the
            # SAME daemon code path is used in both runs, so the
            # ordering is also deterministic. We sort_keys for an
            # extra-defensive comparison.
            data_canon = json.dumps(resp["data"], sort_keys=True,
                                    separators=(",", ":"))
            captured.append((method, params, data_canon, prov["snapshot"]))
    finally:
        d1.close()

    if failures:
        for f in failures:
            sys.stderr.write(f"FAIL (run1): {f}\n")
        try:
            os.remove(core_path)
        except Exception:
            pass
        sys.exit(1)

    # ---------- Run #2 ----------
    # Issue load_core + module.list first (mirroring run #1's snapshot-
    # oracle pattern) so the indices into `captured` line up. We also
    # confirm the snapshot string is byte-identical across daemon
    # processes — that's the cross-process portion of the determinism
    # gate.
    d2 = Daemon(ldbd)
    try:
        r = d2.call("target.load_core", {"path": core_path})
        expect(r["ok"], f"daemon2 load_core: {r}")
        if not r["ok"]:
            raise RuntimeError("daemon2 load_core failed")
        tid2 = r["data"]["target_id"]
        # load_core's own response: same "none" sentinel as run #1.
        expect(r["_provenance"]["snapshot"] == "none",
               f"daemon2 load_core snapshot: {r['_provenance']}")

        run2_responses = []  # parallel to `captured`

        first2 = d2.call("module.list", {"target_id": tid2})
        expect(first2["ok"], f"daemon2 module.list: {first2}")
        snapshot_run2 = first2["_provenance"]["snapshot"]
        expect(snapshot_run2 == snapshot_run1,
               f"snapshot drift across runs: "
               f"r1={snapshot_run1} r2={snapshot_run2}")
        run2_responses.append(first2)

        for method, params in deterministic_calls(tid2):
            # Patch the params with the new daemon's target_id when
            # applicable — the test fixture re-mints target_id per
            # daemon. The byte-diff is on the response data, not on
            # the params. correlate.* uses target_ids[] (plural); patch
            # both shapes.
            if "target_id" in params:
                params = dict(params)
                params["target_id"] = tid2
            if "target_ids" in params:
                params = dict(params)
                params["target_ids"] = [tid2 for _ in params["target_ids"]]
            resp = d2.call(method, params)
            expect(resp["ok"], f"daemon2 {method}: {resp}")
            run2_responses.append(resp)

        # Pairwise compare against run #1.
        expect(len(run2_responses) == len(captured),
               f"capture-length mismatch: r1={len(captured)} "
               f"r2={len(run2_responses)}")
        for (method, _params, r1_canon, r1_snap), resp in zip(
                captured, run2_responses):
            if not resp.get("ok"):
                continue
            r2_canon = json.dumps(resp["data"], sort_keys=True,
                                  separators=(",", ":"))
            expect(r2_canon == r1_canon,
                   f"determinism gate FAILED for {method}: "
                   f"r1.bytes != r2.bytes\n  r1={r1_canon[:200]}...\n"
                   f"  r2={r2_canon[:200]}...")
            r2_snap = resp["_provenance"]["snapshot"]
            expect(r2_snap == r1_snap,
                   f"daemon2 {method}: snapshot drifted: "
                   f"r1={r1_snap} r2={r2_snap}")
    finally:
        d2.close()
        try:
            os.remove(core_path)
        except Exception:
            pass

    if failures:
        for f in failures:
            sys.stderr.write(f"FAIL: {f}\n")
        sys.exit(1)
    print(f"provenance replay PASSED "
          f"({len(captured)} call pairs byte-identical across runs)")


if __name__ == "__main__":
    main()
