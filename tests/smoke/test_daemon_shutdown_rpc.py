#!/usr/bin/env python3
"""Smoke test: `daemon.shutdown` RPC tears the daemon down cleanly.

§2 phase-2 of `docs/35-field-report-followups.md`: a connected client
can ask the daemon to exit by calling `daemon.shutdown`. The handler
returns `{ok: true}` to the caller, then sets the shutdown latch and
writes to the self-pipe so the accept loop wakes up and exits. The
socket inode and lockfile are unlinked on the way out, and the
daemon's exit code is 0.

Test sequence:
  1. Start `ldbd --listen unix:$sock` in the background.
  2. Wait for the socket to appear.
  3. Connect a client, send `daemon.shutdown`, verify ok=true.
  4. Wait for the daemon process to exit; assert rc=0.
  5. Assert the socket and lockfile are gone.
"""
import json
import os
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time


def wait_for_socket(path: str, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(path):
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect(path)
                s.close()
                return True
            except OSError:
                pass
        time.sleep(0.05)
    return False


def usage():
    sys.stderr.write(
        "usage: test_daemon_shutdown_rpc.py <ldbd>\n")
    sys.exit(2)


def main():
    if len(sys.argv) != 2:
        usage()
    ldbd = sys.argv[1]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n")
        sys.exit(1)

    failures = []

    def expect(cond, msg):
        if not cond:
            failures.append(msg)

    with tempfile.TemporaryDirectory() as tmp:
        sock_path = os.path.join(tmp, "ldbd.sock")
        lock_path = sock_path + ".lock"
        daemon = subprocess.Popen(
            [ldbd, "--listen", f"unix:{sock_path}", "--log-level", "error"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            if not wait_for_socket(sock_path, timeout=5.0):
                sys.stderr.write("daemon never bound socket\n")
                sys.exit(1)

            # Connect, send daemon.shutdown, expect ok=true.
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(5.0)
            s.connect(sock_path)
            rw = s.makefile("wb", buffering=0)
            rr = s.makefile("rb", buffering=0)
            req = {"jsonrpc": "2.0", "id": "1",
                   "method": "daemon.shutdown", "params": {}}
            rw.write((json.dumps(req) + "\n").encode("utf-8"))
            rw.flush()
            line = rr.readline()
            expect(bool(line), "no response to daemon.shutdown")
            try:
                resp = json.loads(line)
            except json.JSONDecodeError as e:
                failures.append(f"shutdown reply not JSON: {line!r} ({e})")
                resp = None
            if resp is not None:
                expect(resp.get("ok") is True,
                       f"daemon.shutdown not ok: {resp!r}")
                expect(resp.get("data", {}).get("ok") is True,
                       f"daemon.shutdown data.ok missing: {resp!r}")
            # Close the connection. The daemon's per-connection worker
            # will see EOF on the read(), exit, and let the main
            # thread's join() complete. Without this close the daemon
            # would block on the worker (SO_RCVTIMEO is 300s) even
            # though g_shutdown is set — phase-2 deliberately doesn't
            # interrupt in-flight workers, only stops accepting new
            # connections.
            try:
                rw.close()
                rr.close()
                s.shutdown(socket.SHUT_RDWR)
                s.close()
            except Exception:
                pass

            # Wait for the daemon to exit. Should be quick once the
            # worker sees EOF from the client close above.
            try:
                rc = daemon.wait(timeout=10.0)
            except subprocess.TimeoutExpired:
                failures.append(
                    "daemon did not exit within 10s after "
                    "daemon.shutdown")
                rc = None
            if rc is not None:
                expect(rc == 0, f"daemon exit rc={rc} (expected 0)")

            expect(not os.path.exists(sock_path),
                   f"socket inode should be unlinked: {sock_path}")
            expect(not os.path.exists(lock_path),
                   f"lockfile should be unlinked: {lock_path}")
        finally:
            if daemon.poll() is None:
                daemon.send_signal(signal.SIGTERM)
                try:
                    daemon.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    daemon.kill()

    if failures:
        sys.stderr.write("FAILURES:\n")
        for f in failures:
            sys.stderr.write(f"  - {f}\n")
        sys.exit(1)
    print("OK: daemon.shutdown — clean exit, socket + lockfile unlinked")


if __name__ == "__main__":
    main()
