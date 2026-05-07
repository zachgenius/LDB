#!/usr/bin/env python3
"""Smoke test for target.connect_remote.

Always exercises the negative path: bogus URL → typed -32000 backend
error, malformed URL → -32000, missing url → -32602, bogus target_id
→ -32000.

If lldb-server is discoverable on this dev box (env LDB_LLDB_SERVER,
$LDB_LLDB_ROOT/bin/lldb-server, or `lldb-server` on PATH), also
exercises the positive path: spawn lldb-server gdbserver, parse the
chosen port, target.connect_remote to it, expect a typed state, then
process.detach. The positive path is best-effort — on platforms
where lldb-server can't actually launch an inferior (notably
macOS arm64 with Homebrew LLVM, where it crashes in LaunchProcess),
the test logs a "skipped positive path" message and exits 0 with
just the negative cases verified.
"""
import json
import os
import re
import select
import shutil
import signal
import struct
import subprocess
import sys
import time


def usage():
    sys.stderr.write("usage: test_connect_remote.py <ldbd> <fixture>\n")
    sys.exit(2)


def find_lldb_server():
    env = os.environ.get("LDB_LLDB_SERVER", "")
    if env and os.access(env, os.X_OK):
        return env
    # LLDB_DEBUGSERVER_PATH: set by our ctest harness to the exact binary
    # used by liblldb itself — doubles as lldb-server gdbserver.
    env = os.environ.get("LLDB_DEBUGSERVER_PATH", "")
    if env and os.access(env, os.X_OK):
        return env
    root = os.environ.get("LDB_LLDB_ROOT", "")
    if root:
        cand = os.path.join(root, "bin", "lldb-server")
        if os.access(cand, os.X_OK):
            return cand
    # Hard-coded fallback to the same path our CMake config probes.
    for cand in ("/opt/homebrew/opt/llvm/bin/lldb-server",
                 "/usr/local/opt/llvm/bin/lldb-server"):
        if os.access(cand, os.X_OK):
            return cand
    on_path = shutil.which("lldb-server")
    return on_path or ""


def try_positive_path(call, expect, server, fixture):
    """Spawn lldb-server gdbserver against the fixture, connect, detach.

    Returns True if we successfully exercised the positive path
    (regardless of CHECK results — those are recorded via expect()).
    Returns False if we couldn't get the server up (treated as a
    benign skip).
    """
    # Use --pipe to learn the server's port without a socket probe.
    # A socket probe would connect-then-disconnect to lldb-server, which
    # causes it to exit (gdbserver accepts exactly one debug session).
    # With port=0 the kernel assigns a free port; lldb-server writes it
    # as a binary little-endian uint16 (or ASCII decimal, depending on
    # version) to the pipe fd.
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
        os.close(pipe_r)
        os.close(pipe_w)
        return False
    os.close(pipe_w)

    # Read the port with a 3-second timeout.
    port = None
    ready, _, _ = select.select([pipe_r], [], [], 3.0)
    if ready:
        try:
            raw = os.read(pipe_r, 64)
            # ASCII decimal first (LLVM 22+); fall back to binary uint16 LE
            # (older lldb-server versions).
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
            proc.kill()
            proc.wait(timeout=2)
        except Exception:
            pass
        return False

    try:
        r = call("target.create_empty", {})
        expect(r["ok"], f"create_empty: {r}")
        tid = r["data"]["target_id"]

        r2 = call("target.connect_remote",
                  {"target_id": tid,
                   "url": f"connect://127.0.0.1:{port}"})
        expect(r2["ok"], f"connect_remote: {r2}")
        if r2.get("ok"):
            expect(r2["data"]["state"] in ("stopped", "running"),
                   f"unexpected post-connect state: {r2['data']}")

        r3 = call("process.detach", {"target_id": tid})
        expect(r3["ok"], f"detach after connect_remote: {r3}")
        return True
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


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
        if not cond: failures.append(msg)

    try:
        # Negative path 1: empty url → backend error -32000.
        r1 = call("target.create_empty", {})
        expect(r1["ok"], f"create_empty: {r1}")
        tid = r1["data"]["target_id"]

        # Bogus URL with nothing listening.
        t0 = time.time()
        r2 = call("target.connect_remote",
                  {"target_id": tid, "url": "connect://127.0.0.1:1"})
        elapsed = time.time() - t0
        expect(not r2["ok"] and r2.get("error", {}).get("code") == -32000,
               f"bogus url expected backend error, got {r2}")
        expect(elapsed < 15.0,
               f"bogus url took {elapsed:.2f}s — should be bounded under 15s")

        # Empty URL — malformed.
        r3 = call("target.connect_remote", {"target_id": tid, "url": ""})
        expect(not r3["ok"] and r3.get("error", {}).get("code") == -32000,
               f"empty url expected backend error, got {r3}")

        # Missing url → invalid params -32602.
        r4 = call("target.connect_remote", {"target_id": tid})
        expect(not r4["ok"] and r4.get("error", {}).get("code") == -32602,
               f"missing url expected -32602, got {r4}")

        # Bogus target_id → -32000.
        r5 = call("target.connect_remote",
                  {"target_id": 9999, "url": "connect://127.0.0.1:1"})
        expect(not r5["ok"] and r5.get("error", {}).get("code") == -32000,
               f"bogus target_id expected backend error, got {r5}")

        # Positive path — best-effort, gated on lldb-server availability.
        server = find_lldb_server()
        if not server:
            print("connect_remote smoke: lldb-server not found; "
                  "negative path verified, positive path skipped")
        else:
            ran = try_positive_path(call, expect, server, fixture)
            if ran:
                print("connect_remote smoke: positive path exercised "
                      f"against {server}")
            else:
                print("connect_remote smoke: lldb-server present at "
                      f"{server} but failed to come up; negative path "
                      "verified, positive path skipped")
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
    print("connect_remote smoke test PASSED")


if __name__ == "__main__":
    main()
