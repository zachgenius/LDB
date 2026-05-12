#!/usr/bin/env python3
"""Smoke test for process.list_frames_python (post-V1 plan #14 phase-2).

Phase-2 ships an iterative driver around the Callable that
process.unwind_one (phase-1) exposes for a single step. The
endpoint walks frames until the callable returns null,
returns an incomplete dict, hits max_frames, or trips the
(next_ip, next_sp) cycle guard. Real SBUnwinder hookup so LLDB's
stack walker calls into the callable is a separate item.

SKIPs cleanly when ldbd was built without LDB_ENABLE_PYTHON.
"""
import json
import os
import select
import subprocess
import sys
import tempfile


def usage():
    sys.stderr.write("usage: test_python_unwinder_walk.py <ldbd>\n")
    sys.exit(2)


def main():
    if len(sys.argv) != 2:
        usage()
    ldbd = sys.argv[1]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n"); sys.exit(1)

    store_root = tempfile.mkdtemp(prefix="ldb_smoke_unwinder_walk_")
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
            # ---- Skip-gate: list_frames_python in describe.endpoints ----
            r = call("describe.endpoints")
            assert r["ok"], r
            methods = {e["method"] for e in r["data"]["endpoints"]}
            if "process.list_frames_python" not in methods:
                print("SKIP: process.list_frames_python not in "
                      "describe.endpoints")
                return

            # ---- 1. Bounded walk: returns 3 frames then null ----
            # Unwinder: emits ip+8 / ip+16 / ip+24 then null.
            body = (
                "STEPS = []\n"
                "def run(ctx):\n"
                "    n = len(STEPS)\n"
                "    STEPS.append(ctx['ip'])\n"
                "    if n >= 3:\n"
                "        return None\n"
                "    return {\n"
                "        'next_ip': ctx['ip'] + 8,\n"
                "        'next_sp': ctx['sp'] + 8,\n"
                "        'next_fp': ctx['fp'],\n"
                "    }\n"
            )
            r = call("process.set_python_unwinder",
                     {"target_id": 1, "body": body})
            expect(r["ok"], f"set_python_unwinder: {r}")
            r = call("process.list_frames_python", {
                "target_id": 1, "ip": 0x1000, "sp": 0x2000, "fp": 0x3000,
            })
            expect(r["ok"], f"list_frames_python: {r}")
            data = r.get("data", {})
            frames = data.get("frames", [])
            expect(len(frames) == 3,
                   f"should walk 3 frames before null: {len(frames)} {frames!r}")
            expect(data.get("stop_reason") == "null_return",
                   f"stop_reason should be null_return: {data}")
            if len(frames) == 3:
                expect(frames[0]["next_ip"] == 0x1008,
                       f"frames[0].next_ip: {frames[0]}")
                expect(frames[1]["next_ip"] == 0x1010,
                       f"frames[1].next_ip: {frames[1]}")
                expect(frames[2]["next_ip"] == 0x1018,
                       f"frames[2].next_ip: {frames[2]}")

            # ---- 2. max_frames cap ----
            # Unwinder that never returns null; should stop at max_frames.
            body2 = (
                "def run(ctx):\n"
                "    return {'next_ip': ctx['ip']+1,\n"
                "            'next_sp': ctx['sp']+1,\n"
                "            'next_fp': ctx['fp']}\n"
            )
            r = call("process.set_python_unwinder",
                     {"target_id": 2, "body": body2})
            expect(r["ok"], f"set unwinder 2: {r}")
            r = call("process.list_frames_python", {
                "target_id": 2, "ip": 0, "sp": 0, "fp": 0,
                "max_frames": 5,
            })
            expect(r["ok"], f"list_frames_python max: {r}")
            data = r.get("data", {})
            expect(len(data.get("frames", [])) == 5,
                   f"max=5 should cap at 5 frames: {data}")
            expect(data.get("stop_reason") == "max_frames",
                   f"stop_reason max_frames: {data}")

            # ---- 3. Cycle detection on (next_ip, next_sp) ----
            body3 = (
                "def run(ctx):\n"
                "    return {'next_ip': 0xdead, 'next_sp': 0xbeef,\n"
                "            'next_fp': ctx['fp']}\n"
            )
            r = call("process.set_python_unwinder",
                     {"target_id": 3, "body": body3})
            expect(r["ok"], f"set unwinder 3: {r}")
            r = call("process.list_frames_python", {
                "target_id": 3, "ip": 0, "sp": 0, "fp": 0,
                "max_frames": 100,
            })
            expect(r["ok"], f"cycle walk: {r}")
            data = r.get("data", {})
            expect(data.get("stop_reason") == "cycle",
                   f"stop_reason cycle: {data}")
            expect(len(data.get("frames", [])) == 1,
                   f"cycle should trip after 1 advance: {data}")

            # ---- 4. Incomplete return ----
            body4 = (
                "def run(ctx):\n"
                "    return {'next_ip': 0x42}  # missing next_sp/fp\n"
            )
            r = call("process.set_python_unwinder",
                     {"target_id": 4, "body": body4})
            expect(r["ok"], f"set unwinder 4: {r}")
            r = call("process.list_frames_python", {
                "target_id": 4, "ip": 0, "sp": 0, "fp": 0,
            })
            expect(r["ok"], f"incomplete walk: {r}")
            data = r.get("data", {})
            expect(data.get("stop_reason") == "incomplete_return",
                   f"stop_reason incomplete_return: {data}")
            # The incomplete dict + the ctx that produced it are surfaced.
            frames = data.get("frames", [])
            expect(len(frames) == 1, f"one diag frame: {frames}")
            if frames:
                expect("returned" in frames[0]
                       and "ctx" in frames[0],
                       f"diag frame shape: {frames[0]}")

            # ---- 5. Unset target → -32002 ----
            r = call("process.list_frames_python",
                     {"target_id": 9999, "ip": 0, "sp": 0, "fp": 0})
            expect(not r["ok"],
                   f"unset target should fail: {r}")
            expect(r.get("error", {}).get("code") == -32002,
                   f"unset target code -32002: {r}")
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
        print("OK: process.list_frames_python smoke")
    finally:
        import shutil
        shutil.rmtree(store_root, ignore_errors=True)


if __name__ == "__main__":
    main()
