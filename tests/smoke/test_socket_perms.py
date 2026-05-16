#!/usr/bin/env python3
"""Smoke test: `ldbd --listen unix:PATH` enforces uid-only permissions.

§2 phase 1 of `docs/35-field-report-followups.md` promises:
  * Socket file mode 0600.
  * If the daemon creates the parent directory, mode 0700.

This is the only access control in phase 1 (no token auth, no cross-
user access). A regression here silently widens the daemon's
exposure, so it gets its own pinned test.
"""
import os
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time


def usage():
    sys.stderr.write("usage: test_socket_perms.py <ldbd>\n")
    sys.exit(2)


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

    # Scenario A: caller provides an existing parent dir → only the
    # socket inode is created/chmoded; parent dir untouched.
    with tempfile.TemporaryDirectory() as tmp:
        sock = os.path.join(tmp, "ldbd.sock")
        daemon = subprocess.Popen(
            [ldbd, "--listen", f"unix:{sock}", "--log-level", "error"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            if not wait_for_socket(sock, timeout=5.0):
                err = b""
                try:
                    err = daemon.stderr.read1(4096) if daemon.stderr else b""
                except Exception:
                    pass
                sys.stderr.write(
                    f"daemon never bound socket; stderr={err!r}\n")
                sys.exit(1)
            mode = stat.S_IMODE(os.lstat(sock).st_mode)
            expect(mode == 0o600,
                   f"socket mode should be 0600, got 0o{mode:o}")
        finally:
            try:
                daemon.send_signal(signal.SIGTERM)
                daemon.wait(timeout=5)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait(timeout=2)

    # Scenario B: parent dir does NOT exist → daemon creates it 0700.
    with tempfile.TemporaryDirectory() as outer:
        inner = os.path.join(outer, "run")  # does not exist yet
        sock = os.path.join(inner, "ldbd.sock")
        daemon = subprocess.Popen(
            [ldbd, "--listen", f"unix:{sock}", "--log-level", "error"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            if not wait_for_socket(sock, timeout=5.0):
                err = b""
                try:
                    err = daemon.stderr.read1(4096) if daemon.stderr else b""
                except Exception:
                    pass
                sys.stderr.write(
                    f"daemon never bound socket (auto-mkdir path); "
                    f"stderr={err!r}\n")
                sys.exit(1)
            expect(os.path.isdir(inner),
                   f"daemon should have created parent dir {inner!r}")
            if os.path.isdir(inner):
                dir_mode = stat.S_IMODE(os.lstat(inner).st_mode)
                expect(dir_mode == 0o700,
                       f"auto-created parent dir should be 0700, "
                       f"got 0o{dir_mode:o}")
            sock_mode = stat.S_IMODE(os.lstat(sock).st_mode)
            expect(sock_mode == 0o600,
                   f"socket mode should be 0600, got 0o{sock_mode:o}")
        finally:
            try:
                daemon.send_signal(signal.SIGTERM)
                daemon.wait(timeout=5)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait(timeout=2)

    if failures:
        sys.stderr.write("FAILURES:\n")
        for f in failures:
            sys.stderr.write(f"  - {f}\n")
        sys.exit(1)
    print("OK: socket / parent-dir permissions enforced")


if __name__ == "__main__":
    main()
