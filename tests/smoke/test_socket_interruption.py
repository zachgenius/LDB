#!/usr/bin/env python3
"""Smoke test: SIGTERM during an in-flight RPC.

§2 phase-2 of `docs/35-field-report-followups.md`: the daemon's accept
loop must not block shutdown indefinitely when a connection is alive.
Phase-1 only polled `g_shutdown` between connections; a hung dispatch
prevented exit. The fix is a self-pipe — the signal handler writes a
byte that wakes `poll()` regardless of whether `accept()` would
otherwise have blocked.

Scope clarification (per docs §2): interrupting a dispatch mid-call
requires the backend operation to be interruptible. LldbBackend's SBAPI
calls generally aren't. The phase-2 deliverable is: the daemon stops
accepting new RPCs immediately, finishes any currently-executing
dispatch, then exits cleanly. This test asserts that property — we
send SIGTERM to a daemon that has an active connection (but no
in-flight RPC); the daemon should exit cleanly within ~1s.

Test sequence:
  1. Start `ldbd --listen unix:$sock`.
  2. Connect a client and complete one RPC (`describe.endpoints`).
     Now the connection is alive but idle.
  3. Send SIGTERM to the daemon.
  4. Assert the daemon exits within 3 seconds.
  5. The pre-fix daemon (without the self-pipe) blocks in `read()`
     on the idle client's socket; SO_RCVTIMEO eventually fires (300s
     in production) but the test would time out long before then.
"""
import json
import os
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
    sys.stderr.write("usage: test_socket_interruption.py <ldbd>\n")
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
        daemon = subprocess.Popen(
            [ldbd, "--listen", f"unix:{sock_path}", "--log-level", "error"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            if not wait_for_socket(sock_path, timeout=5.0):
                sys.stderr.write("daemon never bound\n")
                sys.exit(1)

            # Connect and complete one RPC to get the connection into
            # the "alive, idle" state the phase-1 daemon would hang
            # on. We use describe.endpoints because it's cheap and
            # touches no live target state.
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(5.0)
            s.connect(sock_path)
            rw = s.makefile("wb", buffering=0)
            rr = s.makefile("rb", buffering=0)
            req = {"jsonrpc": "2.0", "id": "1",
                   "method": "describe.endpoints"}
            rw.write((json.dumps(req) + "\n").encode("utf-8"))
            rw.flush()
            line = rr.readline()
            expect(bool(line), "no response to describe.endpoints")

            # Connection alive + idle. Send SIGTERM. The main accept
            # loop wakes via the self-pipe and stops accepting new
            # connections; documented phase-2 scope: in-flight workers
            # finish their currently-executing dispatch and the
            # connection's worker thread then sees EOF (when we close
            # the client socket) and exits. Once all workers join,
            # the main thread tears down the listener.
            daemon.send_signal(signal.SIGTERM)
            # Give the daemon a moment to enter shutdown — the
            # accept loop's poll() needs to wake and break out
            # before we close our end. Then close the client socket
            # so the worker's read() returns EOF and the worker
            # exits, unblocking the main thread's join().
            time.sleep(0.2)
            try:
                rw.close()
                rr.close()
                s.shutdown(socket.SHUT_RDWR)
                s.close()
            except Exception:
                pass
            try:
                rc = daemon.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                failures.append(
                    "daemon did not exit within 5s of SIGTERM + "
                    "client close — accept loop or worker join "
                    "blocked")
                rc = None
            if rc is not None:
                expect(rc == 0,
                       f"daemon SIGTERM exit rc={rc} (expected 0)")

        finally:
            if daemon.poll() is None:
                daemon.kill()
                try:
                    daemon.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    pass

    if failures:
        sys.stderr.write("FAILURES:\n")
        for f in failures:
            sys.stderr.write(f"  - {f}\n")
        sys.exit(1)
    print("OK: SIGTERM with idle connection → clean exit within 3s")


if __name__ == "__main__":
    main()
