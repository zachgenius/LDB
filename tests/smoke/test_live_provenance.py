#!/usr/bin/env python3
"""Smoke test for live-target snapshot determinism — slice 1b of v0.3.

Audit doc: docs/04-determinism-audit.md §6.
Spec:      docs/POST-V0.1-PROGRESS.md "Audit-driven corrections folded
           into slice 1b spec".

Live snapshot shape:    live:<gen>:<reg_digest>:<layout_digest>

Contract enforced here (single-process — cross-process determinism
extension is slice 1c):

  1. Two consecutive same-RPC calls against an attached, *not-resumed*
     inferior return byte-identical `data` AND byte-identical
     `_provenance.snapshot`.

  2. The snapshot string matches the documented regex
     ^live:[0-9]+:[0-9a-f]{64}:[0-9a-f]{64}$.

  3. Provenance for live: snapshots reports deterministic=false in this
     slice — the cross-process equality contract that flips it to true
     lands in slice 1c (and requires the deterministic-only view mode).

The "snapshot bumps after resume + stop" arc is exercised in the unit
test (test_live_provenance.cpp) via step_thread, where we have direct
control over the inferior. Smoke covers the byte-identity arc which is
the primary user-facing guarantee.
"""
import json
import os
import re
import subprocess
import sys


LIVE_RE = re.compile(r"^live:[0-9]+:[0-9a-f]{64}:[0-9a-f]{64}$")


def usage():
    sys.stderr.write(
        "usage: test_live_provenance.py <ldbd> <sleeper>\n")
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
        try:
            self.proc.wait(timeout=10)
        except Exception:
            pass


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def main():
    if len(sys.argv) != 3:
        usage()
    ldbd, sleeper = sys.argv[1], sys.argv[2]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n"); sys.exit(1)
    if not os.path.isfile(sleeper):
        sys.stderr.write(f"sleeper missing: {sleeper}\n"); sys.exit(1)

    inferior = subprocess.Popen(
        [sleeper], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True,
    )
    failures = []

    def expect(cond, msg):
        if not cond:
            failures.append(msg)

    try:
        line = inferior.stdout.readline()
        if "READY=" not in line:
            sys.stderr.write(f"sleeper didn't print READY: {line!r}\n")
            sys.exit(1)
        pid_token = line.split()[0]
        assert pid_token.startswith("PID=")
        inferior_pid = int(pid_token[len("PID="):])

        d = Daemon(ldbd)
        try:
            r = d.call("target.create_empty", {})
            expect(r["ok"], f"target.create_empty: {r}")
            target_id = r["data"]["target_id"]

            r = d.call("target.attach",
                       {"target_id": target_id, "pid": inferior_pid})
            expect(r["ok"], f"target.attach: {r}")
            expect(r["data"]["state"] == "stopped",
                   f"expected stopped after attach, got {r['data']}")
            attach_snap = r["_provenance"]["snapshot"]
            expect(LIVE_RE.match(attach_snap) is not None,
                   f"attach snapshot shape mismatch: {attach_snap!r}")
            # `live:` prefix is non-deterministic per the slice-1b
            # design; cross-process equality (which flips it to true)
            # lands in slice 1c.
            expect(r["_provenance"]["deterministic"] is False,
                   f"live snapshot must report deterministic=false in "
                   f"slice 1b, got {r['_provenance']}")

            # Take three back-to-back read-only calls without any
            # resume in between. data + snapshot byte-identity
            # guaranteed.
            calls = [
                ("module.list", {"target_id": target_id}),
                ("thread.list", {"target_id": target_id}),
                ("mem.regions", {"target_id": target_id}),
            ]
            for method, params in calls:
                r1 = d.call(method, params)
                r2 = d.call(method, params)
                expect(r1["ok"] and r2["ok"],
                       f"{method}: ok flags r1={r1.get('ok')} "
                       f"r2={r2.get('ok')}")
                if not (r1.get("ok") and r2.get("ok")):
                    continue
                s1 = r1["_provenance"]["snapshot"]
                s2 = r2["_provenance"]["snapshot"]
                expect(s1 == s2,
                       f"{method}: snapshot drift WITHOUT resume: "
                       f"r1={s1} r2={s2}")
                expect(LIVE_RE.match(s1) is not None,
                       f"{method}: snapshot shape mismatch: {s1!r}")
                d1 = canon(r1["data"])
                d2 = canon(r2["data"])
                expect(d1 == d2,
                       f"{method}: data drifted WITHOUT resume:\n"
                       f"  r1={d1[:200]}...\n"
                       f"  r2={d2[:200]}...")

            # process.state itself is read-only; snapshot must be
            # stable across it too (regression guard for the read-only
            # gen-bump rule from §6.2 of the audit).
            s_pre  = d.call("process.state",
                            {"target_id": target_id}
                            )["_provenance"]["snapshot"]
            s_post = d.call("process.state",
                            {"target_id": target_id}
                            )["_provenance"]["snapshot"]
            expect(s_pre == s_post,
                   f"process.state drift WITHOUT resume: "
                   f"pre={s_pre} post={s_post}")

            # Detach to clean up before the inferior is killed in the
            # outer finally — leaves the sleeper alive and detaches us.
            d.call("process.detach", {"target_id": target_id})
        finally:
            d.close()
    finally:
        try:
            inferior.kill()
        except Exception:
            pass
        try:
            inferior.wait(timeout=5)
        except Exception:
            pass

    if failures:
        for f in failures:
            sys.stderr.write(f"FAIL: {f}\n")
        sys.exit(1)
    print("live provenance smoke test PASSED")


if __name__ == "__main__":
    main()
