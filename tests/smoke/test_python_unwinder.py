#!/usr/bin/env python3
"""Smoke test for process.set_python_unwinder / process.unwind_one
(post-V1 plan #14 phase-1).

Phase-1 ships registration + a test-and-observability invocation
endpoint. Real SBUnwinder hookup so LLDB's stack walker calls the
Python callable during process.list_frames is phase-2 and out of scope
here. The minimum-viable observable contract: the registered callable
ran, its return value flowed back through JSON-RPC, and `stdout`
captures any prints from inside the unwinder.

SKIPs cleanly when ldbd was built without LDB_ENABLE_PYTHON.
"""
import json
import os
import select
import subprocess
import sys
import tempfile


def usage():
    sys.stderr.write("usage: test_python_unwinder.py <ldbd>\n")
    sys.exit(2)


def main():
    if len(sys.argv) != 2:
        usage()
    ldbd = sys.argv[1]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n"); sys.exit(1)

    store_root = tempfile.mkdtemp(prefix="ldb_smoke_unwinder_")
    try:
        env = dict(os.environ)
        env["LDB_STORE_ROOT"] = store_root
        env.setdefault("LLDB_LOG_LEVEL", "error")
        daemon = subprocess.Popen(
            [ldbd, "--stdio", "--log-level", "error"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env, text=True, bufsize=1,
        )

        next_id = [0]
        def call(method, params=None, timeout=15):
            next_id[0] += 1
            rid = f"r{next_id[0]}"
            req = {"jsonrpc": "2.0", "id": rid, "method": method,
                   "params": params or {}}
            daemon.stdin.write(json.dumps(req) + "\n")
            daemon.stdin.flush()
            ready, _, _ = select.select([daemon.stdout], [], [], timeout)
            if not ready:
                try: daemon.kill()
                except Exception: pass
                sys.stderr.write(
                    f"daemon hung on {method} after {timeout}s\n")
                sys.exit(1)
            line = daemon.stdout.readline()
            if not line:
                err = daemon.stderr.read() or ""
                sys.stderr.write(
                    f"daemon closed stdout (stderr was: {err})\n")
                sys.exit(1)
            return json.loads(line)

        failures = []
        def expect(cond, msg):
            if not cond:
                failures.append(msg)

        try:
            # ---- Skip-gate: python unwinder endpoints present? ----
            r = call("describe.endpoints")
            assert r["ok"], r
            methods = {e["method"] for e in r["data"]["endpoints"]}
            for m in ("process.set_python_unwinder", "process.unwind_one"):
                if m not in methods:
                    print(f"SKIP: {m} not in describe.endpoints")
                    return

            # Set an unwinder that adds 8 to ip/sp and returns the result.
            body = (
                "def run(ctx):\n"
                "    print(\"unwinder hit:\", ctx.get('ip'))\n"
                "    return {\n"
                "        'next_ip': ctx['ip'] + 8,\n"
                "        'next_sp': ctx['sp'] + 8,\n"
                "        'next_fp': ctx['fp'],\n"
                "    }\n"
            )

            # ---- Phase-1: registration without a live target ----
            # Phase-1 stores the callable in dispatcher state keyed by
            # target_id; we don't need a real target to test the wire.
            r = call("process.set_python_unwinder",
                     {"target_id": 1, "body": body})
            expect(r["ok"], f"set_python_unwinder: {r}")
            expect(r["data"].get("registered") is True,
                   f"registered should be true: {r['data']}")

            # ---- Invoke against synthetic frame ----
            r = call("process.unwind_one", {
                "target_id": 1, "ip": 0x100, "sp": 0x200, "fp": 0x300,
            })
            expect(r["ok"], f"unwind_one: {r}")
            result = r.get("data", {}).get("result")
            expect(isinstance(result, dict),
                   f"result should be dict: {r}")
            if isinstance(result, dict):
                expect(result.get("next_ip") == 0x108,
                       f"next_ip 0x108: {result}")
                expect(result.get("next_sp") == 0x208,
                       f"next_sp 0x208: {result}")
                expect(result.get("next_fp") == 0x300,
                       f"next_fp 0x300: {result}")
            # Captured stdout pins the stdout-discipline contract.
            captured = r.get("data", {}).get("stdout", "")
            expect("unwinder hit:" in captured,
                   f"captured stdout missing: {captured!r}")

            # ---- SyntaxError at registration → -32602 ----
            r = call("process.set_python_unwinder", {
                "target_id": 2, "body": "def run(ctx)\n  pass\n",
            })
            expect(not r["ok"], f"bad syntax should fail: {r}")
            expect(r.get("error", {}).get("code") == -32602,
                   f"syntax error code: {r}")

            # ---- unwind_one against unset target_id → -32002 ----
            r = call("process.unwind_one",
                     {"target_id": 9999, "ip": 0, "sp": 0, "fp": 0})
            expect(not r["ok"], f"unset target should fail: {r}")
            expect(r.get("error", {}).get("code") == -32002,
                   f"no-unwinder code should be kBadState: {r}")

            # ---- Re-registering replaces the prior callable ----
            body2 = "def run(ctx):\n    return {'note': 'replaced'}\n"
            r = call("process.set_python_unwinder",
                     {"target_id": 1, "body": body2})
            expect(r["ok"], f"re-register: {r}")
            r = call("process.unwind_one",
                     {"target_id": 1, "ip": 0, "sp": 0, "fp": 0})
            result = r.get("data", {}).get("result")
            expect(isinstance(result, dict)
                   and result.get("note") == "replaced",
                   f"replacement should win: {result}")
        finally:
            try:
                daemon.stdin.close()
            except Exception:
                pass
            daemon.wait(timeout=5)

        if failures:
            sys.stderr.write("FAILURES:\n")
            for f in failures:
                sys.stderr.write(f"  - {f}\n")
            sys.exit(1)
        print("OK: process.set_python_unwinder smoke")
    finally:
        import shutil
        shutil.rmtree(store_root, ignore_errors=True)


if __name__ == "__main__":
    main()
