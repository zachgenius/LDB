#!/usr/bin/env python3
"""Smoke test for process.save_core + target.load_core.

Launch sleeper stop-at-entry, save a core, kill, then load_core in the
same daemon and verify the resulting target has modules.
"""
import json
import os
import subprocess
import sys
import tempfile


def usage():
    sys.stderr.write("usage: test_core.py <ldbd> <sleeper>\n")
    sys.exit(2)


def main():
    if len(sys.argv) != 3:
        usage()
    ldbd, sleeper = sys.argv[1], sys.argv[2]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n"); sys.exit(1)
    if not os.path.isfile(sleeper):
        sys.stderr.write(f"sleeper missing: {sleeper}\n"); sys.exit(1)

    core_path = os.path.join(tempfile.gettempdir(),
                             f"ldb_smoke_core_{os.getpid()}.core")
    if os.path.exists(core_path): os.remove(core_path)

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
        r1 = call("target.open", {"path": sleeper})
        expect(r1["ok"], f"target.open: {r1}")
        target_id = r1["data"]["target_id"]

        r2 = call("process.launch",
                  {"target_id": target_id, "stop_at_entry": True})
        expect(r2["ok"], f"process.launch: {r2}")

        r3 = call("process.save_core",
                  {"target_id": target_id, "path": core_path})
        expect(r3["ok"], f"process.save_core: {r3}")
        saved = r3["data"]["saved"]
        if not saved:
            print("WARN: save_core returned saved=false; "
                  "platform may not support it; skipping load_core check")
            call("process.kill", {"target_id": target_id})
        else:
            expect(os.path.exists(core_path),
                   f"save_core claimed success but no file at {core_path}")
            expect(os.path.getsize(core_path) > 0,
                   "core file has zero bytes")

            call("process.kill", {"target_id": target_id})
            call("target.close", {"target_id": target_id})

            r4 = call("target.load_core", {"path": core_path})
            expect(r4["ok"], f"target.load_core: {r4}")
            new_target_id = r4["data"]["target_id"]
            expect(new_target_id != 0, "load_core returned target_id 0")
            expect(len(r4["data"]["modules"]) >= 1,
                   "load_core target has no modules")

            r5 = call("thread.list", {"target_id": new_target_id})
            expect(r5["ok"], f"thread.list on core: {r5}")
            expect(len(r5["data"]["threads"]) >= 1,
                   f"core has no threads: {r5['data']}")

        # Missing path → -32602.
        r6 = call("target.load_core", {})
        expect(not r6["ok"] and r6.get("error", {}).get("code") == -32602,
               f"missing path expected -32602: {r6}")

        # Nonexistent path → -32000 backend error.
        r7 = call("target.load_core", {"path": "/nonexistent/no.core"})
        expect(not r7["ok"] and r7.get("error", {}).get("code") == -32000,
               f"missing core file expected -32000: {r7}")
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        proc.wait(timeout=10)
        try:
            if os.path.exists(core_path): os.remove(core_path)
        except Exception:
            pass

    if failures:
        for f in failures:
            sys.stderr.write(f"FAIL: {f}\n")
        sys.exit(1)
    print("core smoke test PASSED")


if __name__ == "__main__":
    main()
