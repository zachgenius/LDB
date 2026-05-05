#!/usr/bin/env python3
"""Smoke test for frame.locals / frame.args / frame.registers.

Drives ldbd interactively, launches the structs fixture stop-at-entry,
discovers a tid via thread.list, then exercises all three frame.*
endpoints. Asserts response shapes and verifies that view.fields
projection drops other keys.
"""
import json
import os
import subprocess
import sys


def usage():
    sys.stderr.write("usage: test_frame_values.py <ldbd> <fixture>\n")
    sys.exit(2)


def main():
    if len(sys.argv) != 3:
        usage()
    ldbd, fixture = sys.argv[1], sys.argv[2]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n"); sys.exit(1)
    if not os.path.isfile(fixture):
        sys.stderr.write(f"fixture missing: {fixture}\n"); sys.exit(1)

    env = dict(os.environ)
    env.setdefault("LLDB_LOG_LEVEL", "error")

    proc = subprocess.Popen(
        [ldbd, "--stdio", "--log-level", "error"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
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
            sys.stderr.write(f"daemon closed stdout (stderr was: {stderr})\n")
            sys.exit(1)
        return json.loads(line)

    failures = []
    def expect(cond, msg):
        if not cond:
            failures.append(msg)

    try:
        r1 = call("target.open", {"path": fixture})
        expect(r1["ok"], f"target.open: {r1}")

        r2 = call("process.launch",
                  {"target_id": 1, "stop_at_entry": True})
        expect(r2["ok"], f"process.launch: {r2}")
        expect(r2["data"]["state"] == "stopped",
               f"expected stopped, got {r2['data']['state']}")

        r3 = call("thread.list", {"target_id": 1})
        expect(r3["ok"], f"thread.list: {r3}")
        threads = r3["data"]["threads"]
        expect(len(threads) >= 1, "no threads after stop-at-entry")
        if not threads:
            raise SystemExit(1)
        tid = threads[0]["tid"]

        # frame.locals — entry-frame may be empty; we just want the shape.
        r4 = call("frame.locals", {"target_id": 1, "tid": tid})
        expect(r4["ok"], f"frame.locals: {r4}")
        expect("locals" in r4["data"], f"missing 'locals': {r4['data']}")
        expect("total" in r4["data"], f"missing 'total': {r4['data']}")
        for v in r4["data"]["locals"]:
            expect(v.get("kind") == "local",
                   f"local kind expected, got {v.get('kind')}")

        # frame.args — same shape rules.
        r5 = call("frame.args", {"target_id": 1, "tid": tid})
        expect(r5["ok"], f"frame.args: {r5}")
        expect("args" in r5["data"], f"missing 'args': {r5['data']}")
        for v in r5["data"]["args"]:
            expect(v.get("kind") == "arg",
                   f"arg kind expected, got {v.get('kind')}")

        # frame.registers — must be non-empty on a stopped thread.
        r6 = call("frame.registers", {"target_id": 1, "tid": tid})
        expect(r6["ok"], f"frame.registers: {r6}")
        regs = r6["data"]["registers"]
        expect(len(regs) >= 1, "expected at least one register")
        # Some register named pc / rip / eip should be present.
        names = {r["name"] for r in regs}
        expect(names & {"pc", "rip", "eip"} != set(),
               f"no PC-class register found in {sorted(names)[:8]}...")
        # Every register has the expected keys.
        for r in regs[:5]:
            expect("name" in r and "type" in r and "kind" in r,
                   f"register missing keys: {r}")
            expect(r["kind"] == "register",
                   f"register kind mismatch: {r}")

        # view.fields projection drops other keys.
        r7 = call("frame.registers",
                  {"target_id": 1, "tid": tid,
                   "view": {"fields": ["name"], "limit": 3}})
        expect(r7["ok"], f"frame.registers w/ view: {r7}")
        for r in r7["data"]["registers"]:
            expect(set(r.keys()) <= {"name"},
                   f"view.fields didn't project: {r}")
        expect(len(r7["data"]["registers"]) <= 3,
               f"view.limit ignored: {len(r7['data']['registers'])}")

        # Bogus tid → backend error -32000.
        r8 = call("frame.registers",
                  {"target_id": 1, "tid": 0xDEAD_BEEF})
        expect(not r8["ok"] and r8.get("error", {}).get("code") == -32000,
               f"expected backend error for bad tid, got {r8}")

        # Missing tid → -32602.
        r9 = call("frame.locals", {"target_id": 1})
        expect(not r9["ok"] and r9.get("error", {}).get("code") == -32602,
               f"expected -32602 for missing tid, got {r9}")

        # Cleanup.
        call("process.kill", {"target_id": 1})
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
    print("frame values smoke test PASSED")


if __name__ == "__main__":
    main()
