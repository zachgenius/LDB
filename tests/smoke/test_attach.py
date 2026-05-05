#!/usr/bin/env python3
"""Smoke test for target.create_empty + target.attach + process.detach.

Spawns the sleeper fixture, parses its PID from stdout, then drives
ldbd to attach by pid, verify state, and detach.
"""
import json
import os
import signal
import subprocess
import sys
import time


def usage():
    sys.stderr.write("usage: test_attach.py <ldbd> <sleeper>\n")
    sys.exit(2)


def main():
    if len(sys.argv) != 3:
        usage()
    ldbd, sleeper = sys.argv[1], sys.argv[2]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n"); sys.exit(1)
    if not os.path.isfile(sleeper):
        sys.stderr.write(f"sleeper missing: {sleeper}\n"); sys.exit(1)

    inferior = subprocess.Popen(
        [sleeper], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        # Wait for the READY line.
        line = inferior.stdout.readline()
        if "READY=" not in line:
            sys.stderr.write(f"sleeper didn't print READY: {line}\n")
            sys.exit(1)
        # Extract PID — line is: PID=<n> READY=<marker>
        pid_token = line.split()[0]  # "PID=<n>"
        assert pid_token.startswith("PID=")
        inferior_pid = int(pid_token[len("PID="):])

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
            if not cond: failures.append(msg)

        try:
            r1 = call("target.create_empty", {})
            expect(r1["ok"], f"target.create_empty: {r1}")
            target_id = r1["data"]["target_id"]
            expect(target_id > 0, f"bad target_id: {target_id}")

            r2 = call("target.attach",
                      {"target_id": target_id, "pid": inferior_pid})
            expect(r2["ok"], f"target.attach: {r2}")
            expect(r2["data"]["state"] == "stopped",
                   f"expected stopped after attach, got {r2['data']}")
            expect(r2["data"]["pid"] == inferior_pid,
                   f"pid mismatch: {r2['data']['pid']} != {inferior_pid}")

            r3 = call("process.detach", {"target_id": target_id})
            expect(r3["ok"], f"process.detach: {r3}")
            expect(r3["data"]["state"] in ("detached", "none"),
                   f"unexpected post-detach state: {r3['data']}")

            # Bad pid → backend error.
            r4 = call("target.attach", {"target_id": target_id, "pid": 0})
            expect(not r4["ok"] and r4.get("error", {}).get("code") == -32000,
                   f"bad pid expected backend error, got {r4}")

            # Missing pid → -32602.
            r5 = call("target.attach", {"target_id": target_id})
            expect(not r5["ok"] and r5.get("error", {}).get("code") == -32602,
                   f"missing pid expected -32602, got {r5}")
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
        print("attach smoke test PASSED")
    finally:
        try:
            inferior.kill()
        except Exception:
            pass
        try:
            inferior.wait(timeout=5)
        except Exception:
            pass


if __name__ == "__main__":
    main()
