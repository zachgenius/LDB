#!/usr/bin/env python3
"""Smoke test for target.connect_remote_rsp (post-V1 #17 phase-1).

Exercises the new own-RSP-client dispatcher endpoint end-to-end:

  1. Spawn `lldb-server gdbserver localhost:0` against ldb_fix_sleeper.
  2. Read the chosen port via --pipe (kernel-allocated when port=0).
  3. Drive ldbd: target.connect_remote_rsp url=connect://127.0.0.1:PORT.
  4. Expect ok + process_status with a `state` field.
  5. target.close (joins the channel thread, closes the socket).
  6. Tear down lldb-server.

SKIPs cleanly when lldb-server isn't discoverable. The negative path
(malformed url, refused port) is covered by the unit suite, so this
smoke focuses on the live wire round-trip.
"""
import json
import os
import select
import shutil
import signal
import struct
import subprocess
import sys
import time


def usage():
    sys.stderr.write("usage: test_rsp_connect.py <ldbd> <fixture>\n")
    sys.exit(2)


def find_lldb_server():
    env = os.environ.get("LDB_LLDB_SERVER", "")
    if env and os.access(env, os.X_OK):
        return env
    env = os.environ.get("LLDB_DEBUGSERVER_PATH", "")
    if env and os.access(env, os.X_OK):
        return env
    root = os.environ.get("LDB_LLDB_ROOT", "")
    if root:
        cand = os.path.join(root, "bin", "lldb-server")
        if os.access(cand, os.X_OK):
            return cand
    for cand in ("/opt/llvm-22/bin/lldb-server",
                 "/opt/homebrew/opt/llvm/bin/lldb-server",
                 "/usr/local/opt/llvm/bin/lldb-server"):
        if os.access(cand, os.X_OK):
            return cand
    on_path = shutil.which("lldb-server")
    return on_path or ""


def spawn_lldb_server(server, fixture):
    """Spawn lldb-server gdbserver and read its port. Returns (proc, port)
    or (None, None) on any failure (signals SKIP-equivalent to the caller)."""
    pipe_r, pipe_w = os.pipe()
    try:
        proc = subprocess.Popen(
            [server, "gdbserver",
             "--pipe", str(pipe_w),
             "127.0.0.1:0", "--", fixture],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            pass_fds=(pipe_w,),
        )
    except OSError:
        os.close(pipe_r); os.close(pipe_w)
        return None, None
    os.close(pipe_w)

    port = None
    ready, _, _ = select.select([pipe_r], [], [], 5.0)
    if ready:
        try:
            raw = os.read(pipe_r, 64)
            text = raw.rstrip(b"\x00 \t\n\r")
            if text and all(48 <= b <= 57 for b in text):
                p = int(text)
                if 1 <= p <= 65535:
                    port = p
            if port is None and len(raw) >= 2:
                p = struct.unpack_from("<H", raw)[0]
                if 1 <= p <= 65535:
                    port = p
        except (OSError, ValueError, struct.error):
            pass
    os.close(pipe_r)

    if port is None or proc.poll() is not None:
        try:
            proc.kill(); proc.wait(timeout=2)
        except Exception:
            pass
        return None, None
    return proc, port


def main():
    if len(sys.argv) != 3:
        usage()
    ldbd, fixture = sys.argv[1], sys.argv[2]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n"); sys.exit(1)
    if not os.path.isfile(fixture):
        sys.stderr.write(f"fixture missing: {fixture}\n"); sys.exit(1)

    server = find_lldb_server()
    if not server:
        print("rsp_connect smoke: lldb-server not found — SKIP")
        return

    env = dict(os.environ)
    env.setdefault("LLDB_LOG_LEVEL", "error")

    ldbd_proc = subprocess.Popen(
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
        ldbd_proc.stdin.write(json.dumps(req) + "\n")
        ldbd_proc.stdin.flush()
        line = ldbd_proc.stdout.readline()
        if not line:
            stderr = ldbd_proc.stderr.read()
            sys.stderr.write(f"daemon closed stdout (stderr: {stderr})\n")
            sys.exit(1)
        return json.loads(line)

    failures = []
    def expect(cond, msg):
        if not cond: failures.append(msg)

    server_proc = None
    try:
        # Bring up the gdbserver against the sleeper fixture.
        server_proc, port = spawn_lldb_server(server, fixture)
        if server_proc is None:
            print(f"rsp_connect smoke: lldb-server at {server} failed "
                  "to come up — SKIP positive path")
            # Negative path is the unit-test layer's job; we don't
            # re-exercise it here.
            return

        # Mint a target.
        r1 = call("target.create_empty", {})
        expect(r1["ok"], f"create_empty: {r1}")
        if not r1["ok"]:
            return
        tid = r1["data"]["target_id"]

        # The new endpoint — drive the own RSP client.
        t0 = time.time()
        r2 = call("target.connect_remote_rsp",
                  {"target_id": tid,
                   "url": f"connect://127.0.0.1:{port}"})
        elapsed = time.time() - t0
        expect(r2["ok"], f"connect_remote_rsp: {r2}")
        expect(elapsed < 15.0,
               f"connect_remote_rsp took {elapsed:.2f}s — should be bounded")
        if r2.get("ok"):
            state = r2["data"].get("state")
            expect(state in ("stopped", "running", "exited"),
                   f"unexpected state field: {r2['data']}")
            expect("target_id" in r2["data"],
                   f"target_id missing from response: {r2['data']}")

        # target.close joins the channel reader thread + closes the fd.
        r3 = call("target.close", {"target_id": tid})
        expect(r3["ok"], f"target.close: {r3}")

        # Tear down lldb-server. gdbserver typically exits when the
        # debug session ends; if it didn't notice, terminate() it.
        print(f"rsp_connect smoke: positive path exercised against {server}")
    finally:
        try:
            ldbd_proc.stdin.close()
        except Exception:
            pass
        ldbd_proc.wait(timeout=10)
        if server_proc is not None:
            try:
                server_proc.terminate()
                server_proc.wait(timeout=3)
            except Exception:
                try:
                    server_proc.kill()
                except Exception:
                    pass

    if failures:
        for f in failures:
            sys.stderr.write(f"FAIL: {f}\n")
        sys.exit(1)
    print("rsp_connect smoke test PASSED")


if __name__ == "__main__":
    main()
