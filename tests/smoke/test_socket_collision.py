#!/usr/bin/env python3
"""Smoke test: two `ldbd --listen unix:$same_path` race.

§2 phase 1 of `docs/35-field-report-followups.md` promises an exclusive
`flock()` on `${sock}.lock` so a second daemon trying to bind the same
path exits 1 with a clear stderr message. This test starts daemon #1,
waits for it to bind, then spawns daemon #2 against the same path and
asserts it exits non-zero with a useful diagnostic.
"""
import os
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time


def read_stderr_nonblocking(proc, timeout: float = 0.2) -> bytes:
    """Drain whatever stderr is ready, with a short timeout.

    Bounded wait avoids blocking the test runner when the daemon is
    alive but hasn't logged anything yet.
    """
    if not proc.stderr:
        return b""
    try:
        ready, _, _ = select.select([proc.stderr], [], [], timeout)
    except (OSError, ValueError):
        return b""
    if not ready:
        return b""
    try:
        return proc.stderr.read1(4096) or b""
    except Exception:
        return b""


def usage():
    sys.stderr.write("usage: test_socket_collision.py <ldbd>\n")
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

    with tempfile.TemporaryDirectory() as tmp:
        sock = os.path.join(tmp, "ldbd.sock")

        first = subprocess.Popen(
            [ldbd, "--listen", f"unix:{sock}", "--log-level", "error"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            if not wait_for_socket(sock, timeout=5.0):
                err = read_stderr_nonblocking(first)
                sys.stderr.write(
                    f"first daemon never bound socket; stderr={err!r}\n")
                sys.exit(1)

            # Second daemon on the SAME path should fail fast.
            second = subprocess.run(
                [ldbd, "--listen", f"unix:{sock}", "--log-level", "error"],
                capture_output=True,
                text=True,
                timeout=10.0,
            )
            expect(second.returncode != 0,
                   f"second daemon should fail: rc={second.returncode} "
                   f"stdout={second.stdout!r} stderr={second.stderr!r}")
            stderr = second.stderr.lower()
            expect("already" in stderr or "listening" in stderr
                   or "bound" in stderr or "lock" in stderr,
                   f"second daemon stderr should explain collision: "
                   f"{second.stderr!r}")
        finally:
            try:
                first.send_signal(signal.SIGTERM)
                first.wait(timeout=5)
            except subprocess.TimeoutExpired:
                first.kill()
                first.wait(timeout=2)

    if failures:
        sys.stderr.write("FAILURES:\n")
        for f in failures:
            sys.stderr.write(f"  - {f}\n")
        sys.exit(1)
    print("OK: socket-collision second daemon refused")


if __name__ == "__main__":
    main()
