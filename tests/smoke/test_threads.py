#!/usr/bin/env python3
"""Smoke test for thread.list and thread.frames.

Spawns ldbd once, drives the JSON-RPC channel interactively, uses
earlier responses to inform later requests (the TID isn't known
until after process.launch). Pattern reusable for any other smoke
test that needs cross-request data flow.
"""
import json
import os
import subprocess
import sys


def usage():
    sys.stderr.write("usage: test_threads.py <ldbd> <fixture>\n")
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

        # thread.list pre-launch returns empty.
        r2 = call("thread.list", {"target_id": 1})
        expect(r2["ok"], f"thread.list pre-launch: {r2}")
        expect(r2["data"]["threads"] == [],
               f"thread.list pre-launch should be empty, got {r2['data']}")

        # Launch with stop-at-entry.
        r3 = call("process.launch",
                  {"target_id": 1, "stop_at_entry": True})
        expect(r3["ok"], f"process.launch: {r3}")
        expect(r3["data"]["state"] == "stopped",
               f"expected state=stopped, got {r3['data']['state']}")

        # Thread list now has entries.
        r4 = call("thread.list", {"target_id": 1})
        expect(r4["ok"], f"thread.list post-launch: {r4}")
        threads = r4["data"]["threads"]
        expect(len(threads) >= 1, "expected >=1 thread post-launch")
        if not threads:
            raise SystemExit(1)
        t0 = threads[0]
        expect(t0["state"] == "stopped",
               f"thread state should be stopped, got {t0['state']}")
        expect(t0["tid"] != 0, "tid must be non-zero")
        expect(t0["index"] >= 1, "index must be 1-based")
        expect(t0["pc"] != 0, "pc must be non-zero on a stopped thread")

        # Frames for that thread.
        r5 = call("thread.frames", {"target_id": 1, "tid": t0["tid"]})
        expect(r5["ok"], f"thread.frames: {r5}")
        frames = r5["data"]["frames"]
        expect(len(frames) >= 1, "expected >=1 frame")
        if frames:
            expect(frames[0]["index"] == 0, "innermost frame index should be 0")
            expect(frames[0]["pc"] != 0, "innermost frame pc should be non-zero")

        # max_depth bound.
        r6 = call("thread.frames",
                  {"target_id": 1, "tid": t0["tid"], "max_depth": 1})
        expect(r6["ok"], f"thread.frames max_depth=1: {r6}")
        expect(len(r6["data"]["frames"]) <= 1,
               f"max_depth=1 yielded {len(r6['data']['frames'])} frames")

        # Bogus tid → backend error -32000.
        r7 = call("thread.frames",
                  {"target_id": 1, "tid": 0xDEAD_BEEF})
        expect(not r7["ok"] and r7.get("error", {}).get("code") == -32000,
               f"bogus tid expected backend error, got {r7}")

        # Missing tid → invalid params -32602.
        r8 = call("thread.frames", {"target_id": 1})
        expect(not r8["ok"] and r8.get("error", {}).get("code") == -32602,
               f"missing tid expected -32602, got {r8}")

        # Cleanup.
        r9 = call("process.kill", {"target_id": 1})
        expect(r9["ok"], f"process.kill: {r9}")
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
    print("thread smoke test PASSED")


if __name__ == "__main__":
    main()
