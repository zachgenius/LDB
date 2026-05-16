#!/usr/bin/env python3
"""Smoke test: `ldbd --listen-idle-timeout N` exits after N idle seconds.

§2 phase-2 of `docs/35-field-report-followups.md`: an operator who
wants the daemon to die quietly after a burst of activity finishes can
opt into an idle timeout. The accept loop's poll() blocks with a
timeout argument; when no new connection arrives within N seconds AND
no workers are alive, the daemon shuts down cleanly.

The "no workers alive" qualifier matters because a long-lived agent
session might sit idle on a connected socket for >N seconds while
deciding what to do next. Killing the daemon out from under it would
be hostile; we only fire the idle timeout when nobody's home.

Test sequence:
  1. Start `ldbd --listen-idle-timeout 2 --listen unix:$sock`.
  2. Wait 3 seconds with no clients.
  3. Assert daemon exited cleanly (rc=0, socket+lockfile unlinked).
"""
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
    sys.stderr.write("usage: test_socket_idle_timeout.py <ldbd>\n")
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
            [ldbd, "--listen", f"unix:{sock_path}",
             "--listen-idle-timeout", "2",
             "--log-level", "error"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            if not wait_for_socket(sock_path, timeout=5.0):
                sys.stderr.write("daemon never bound\n")
                sys.exit(1)

            # Wait beyond the idle timeout. No connections; the daemon
            # should exit on its own.
            try:
                rc = daemon.wait(timeout=8.0)
            except subprocess.TimeoutExpired:
                failures.append(
                    "daemon did not exit within 8s despite "
                    "--listen-idle-timeout 2 and no connections")
                rc = None
            if rc is not None:
                expect(rc == 0, f"daemon exit rc={rc} (expected 0)")
                expect(not os.path.exists(sock_path),
                       f"socket should be unlinked: {sock_path}")
                expect(not os.path.exists(lock_path),
                       f"lockfile should be unlinked: {lock_path}")
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
    print("OK: --listen-idle-timeout fires cleanly when idle")


if __name__ == "__main__":
    main()
