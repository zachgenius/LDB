#!/usr/bin/env python3
"""Smoke test for session.fork + session.replay (post-V1 plan #16 phase-1).

End-to-end exercise of the replay surface (docs/24-session-fork-replay.md):
  • Create a session against a real ldbd + ldb_fix_structs fixture.
  • Attach; run a handful of deterministic-ish RPCs (target.open,
    module.list, type.layout, symbol.find, hello, describe.endpoints).
  • Detach.
  • Call session.replay against that session. Assert:
      - the response shape matches §2.2 (every documented key present),
      - replayed > 0,
      - errors == 0,
      - replay is idempotent (running it twice yields the same summary
        modulo any wall-clock fields that the response shape doesn't
        expose anyway).
  • Fork the session at a specific seq, confirm rows_copied matches
    the cut, and the child + parent are both intact.

Uses LDB_STORE_ROOT pointed at a per-test tmpdir — never touches ~/.ldb.
"""
import json
import os
import subprocess
import sys
import tempfile


def usage():
    sys.stderr.write(
        "usage: test_session_replay.py <ldbd> <structs-fixture>\n")
    sys.exit(2)


def main():
    if len(sys.argv) != 3:
        usage()
    ldbd, fixture = sys.argv[1], sys.argv[2]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n"); sys.exit(1)
    if not os.path.isfile(fixture):
        sys.stderr.write(f"fixture missing: {fixture}\n"); sys.exit(1)

    store_root = tempfile.mkdtemp(prefix="ldb_smoke_replay_")

    env = dict(os.environ)
    env["LDB_STORE_ROOT"] = store_root
    env.setdefault("LLDB_LOG_LEVEL", "error")
    proc = subprocess.Popen(
        [ldbd, "--stdio", "--log-level", "error"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env, text=True, bufsize=1,
    )

    next_id = [0]
    def call(method, params=None):
        next_id[0] += 1
        rid = f"r{next_id[0]}"
        req = {"jsonrpc": "2.0", "id": rid, "method": method,
               "params": params or {}}
        proc.stdin.write(json.dumps(req) + "\n")
        proc.stdin.flush()
        line = proc.stdout.readline()
        if not line:
            stderr = proc.stderr.read()
            sys.stderr.write(
                f"daemon closed stdout (stderr was: {stderr})\n")
            sys.exit(1)
        return json.loads(line)

    failures = []
    def expect(cond, msg):
        if not cond: failures.append(msg)

    try:
        # --- describe.endpoints lists session.fork + session.replay -----
        r0 = call("describe.endpoints")
        expect(r0["ok"], f"describe.endpoints: {r0}")
        methods = {e["method"] for e in r0["data"]["endpoints"]}
        expect("session.fork"   in methods, "session.fork not advertised")
        expect("session.replay" in methods, "session.replay not advertised")

        # --- create + attach session --------------------------------------
        c = call("session.create", {"name": "replay-smoke"})
        expect(c["ok"], f"session.create: {c}")
        if not c["ok"]:
            raise RuntimeError("session.create failed")
        sid = c["data"]["id"]

        a = call("session.attach", {"id": sid})
        expect(a["ok"], f"session.attach: {a}")

        # --- run a handful of RPCs against the fixture --------------------
        t = call("target.open", {"path": fixture})
        expect(t["ok"], f"target.open: {t}")
        tid = t["data"]["target_id"]

        call("module.list", {"target_id": tid})
        call("type.layout", {"target_id": tid, "name": "point2"})
        call("symbol.find", {"target_id": tid, "name": "main"})
        # A couple of no-target deterministic-shape calls.
        call("hello")
        call("describe.endpoints")

        d = call("session.detach")
        expect(d["ok"], f"session.detach: {d}")

        # --- session.replay shape -----------------------------------------
        rp = call("session.replay", {"session_id": sid})
        expect(rp["ok"], f"session.replay: {rp}")
        if not rp["ok"]:
            raise RuntimeError("session.replay failed")
        rd = rp["data"]
        for k in ("session_id", "total_steps", "replayed", "skipped",
                  "deterministic_matches", "deterministic_mismatches",
                  "errors", "divergences"):
            expect(k in rd, f"replay response missing key: {k}")
        expect(rd["session_id"] == sid,
               f"replay session_id mismatch: {rd['session_id']} vs {sid}")
        expect(rd["errors"] == 0,
               f"replay errors > 0: {rd.get('divergences')}")
        expect(rd["replayed"] > 0,
               f"replay replayed == 0; nothing got dispatched: {rd}")
        # session.* meta-rows accounted for (attach + detach at minimum).
        expect(rd["skipped"] >= 2,
               f"replay skipped should be >= 2 (attach + detach): {rd}")

        # --- idempotency: re-run yields the same counters -----------------
        rp2 = call("session.replay", {"session_id": sid})
        expect(rp2["ok"], f"session.replay rerun: {rp2}")
        for k in ("total_steps", "replayed", "skipped",
                  "deterministic_matches", "deterministic_mismatches",
                  "errors"):
            expect(rd[k] == rp2["data"][k],
                   f"replay drift on {k}: {rd[k]} vs {rp2['data'][k]}")

        # --- session.fork: rows_copied == captured count ------------------
        info = call("session.info", {"id": sid})
        expect(info["ok"], f"session.info: {info}")
        total_count = info["data"]["call_count"]

        fork = call("session.fork", {"source_session_id": sid,
                                      "name": "smoke-fork"})
        expect(fork["ok"], f"session.fork: {fork}")
        if not fork["ok"]:
            raise RuntimeError("session.fork failed")
        child_id = fork["data"]["session_id"]
        expect(child_id != sid, "fork must produce a new id")
        expect(fork["data"]["rows_copied"] == total_count,
               f"fork copied {fork['data']['rows_copied']} rows, "
               f"parent has {total_count}")
        expect(fork["data"]["name"] == "smoke-fork",
               f"fork name: {fork['data']['name']}")

        # Parent and child both visible in session.list.
        lst = call("session.list")
        expect(lst["ok"], f"session.list: {lst}")
        listed = {s["id"] for s in lst["data"]["sessions"]}
        expect(sid in listed, f"parent missing from list")
        expect(child_id in listed, f"child missing from list")

        # --- fork cut at seq=2: rows_copied == 2 --------------------------
        fork_cut = call("session.fork",
                         {"source_session_id": sid,
                          "name": "smoke-fork-cut",
                          "until_seq": 2})
        expect(fork_cut["ok"], f"session.fork cut: {fork_cut}")
        if fork_cut["ok"]:
            expect(fork_cut["data"]["rows_copied"] == 2,
                   f"fork cut copied {fork_cut['data']['rows_copied']} rows")
            expect(fork_cut["data"]["forked_at_seq"] == 2,
                   f"forked_at_seq: {fork_cut['data']['forked_at_seq']}")

    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        proc.wait(timeout=10)

    if failures:
        for f in failures:
            sys.stderr.write(f"FAIL: {f}\n")
        sys.exit(1)

    print(f"session_replay PASSED "
          f"(sid={sid[:8]}.., child={child_id[:8]}.., "
          f"replayed={rd['replayed']}, skipped={rd['skipped']})")


if __name__ == "__main__":
    main()
