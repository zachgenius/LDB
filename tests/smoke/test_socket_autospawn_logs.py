#!/usr/bin/env python3
"""Smoke test: §2 phase-2 I4 — daemon stderr lines stay atomic under
concurrent autospawn races.

When N clients race-spawn N daemons against the same socket path,
the (N-1) losers all write diagnostic lines to the SAME stderr
destination (operators commonly redirect via LDB_LDBD_LOG_FILE so
all daemons append to a shared log). Pre-fix each diagnostic was
emitted as a chain of `std::cerr << "ldbd: ..." << pid << ... <<
"\n"` shifts; libstdc++ flushes each shift as its own write(2)
syscall, and concurrent processes interleave them — operators see
"ldbd: another daemon is already lis ldbd: another daemon is alr".

Fix: build each diagnostic as a single std::string and emit it with
one fwrite. POSIX guarantees a single write of ≤PIPE_BUF (typically
512) bytes to a regular file is atomic w.r.t. other writers; our
diagnostic lines fit comfortably.

This test races several daemons trying to bind the same path; only
one will win (flock + bind exclusivity), the rest emit "another
daemon is already listening" diagnostics. We capture all stderr
into one shared file and verify every line starts with "ldbd: " —
i.e. no diagnostic was torn across a write boundary.
"""
import os
import signal
import subprocess
import sys
import tempfile
import time


def usage():
    sys.stderr.write("usage: test_socket_autospawn_logs.py <ldbd>\n")
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
        log_path = os.path.join(tmp, "ldbd.log")
        # Open ONE log file shared across N daemon processes — this
        # is the configuration that reproduces the I4 interleave
        # pre-fix. O_APPEND means each write lands at the file's
        # current end, but a multi-write line can still be torn
        # because the end-of-file pointer advances between writes.
        log_fh = open(log_path, "ab")
        N = 10
        daemons = []
        try:
            for _ in range(N):
                p = subprocess.Popen(
                    [ldbd, "--listen", f"unix:{sock_path}",
                     "--log-level", "error"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=log_fh,
                )
                daemons.append(p)
            # Give the losers time to exit; the winner stays up.
            time.sleep(1.0)

            # Find the winner (exit code None) and SIGTERM it.
            winner = None
            losers = []
            for p in daemons:
                if p.poll() is None:
                    winner = p
                else:
                    losers.append(p)

            expect(winner is not None,
                   "no daemon won the bind race; all exited")
            expect(len(losers) >= 1,
                   f"expected at least one loser; got {len(losers)} "
                   f"(N={N})")

            # Shut the winner down.
            if winner is not None:
                winner.send_signal(signal.SIGTERM)
                try:
                    winner.wait(timeout=5.0)
                except subprocess.TimeoutExpired:
                    winner.kill()
                    winner.wait(timeout=2.0)

            # Wait for any stragglers.
            for p in daemons:
                try:
                    p.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    p.kill()
        finally:
            log_fh.flush()
            log_fh.close()
            for p in daemons:
                if p.poll() is None:
                    p.kill()

        # Now inspect the log. Every line MUST start with "ldbd: "
        # (the prefix is the load-bearing invariant: a torn write
        # would leave a partial line whose start is in the middle
        # of "another daemon" or "refusing"). Empty trailing line
        # after the final newline is fine.
        with open(log_path, "rb") as f:
            content = f.read()
        lines = content.splitlines()
        expect(len(lines) >= 1,
               f"expected at least 1 diagnostic line; got {len(lines)} "
               f"(content={content!r})")
        for i, line in enumerate(lines):
            if not line:
                continue
            expect(line.startswith(b"ldbd: "),
                   f"line {i} does not start with 'ldbd: ' "
                   f"(possible torn write): {line!r}")

    if failures:
        sys.stderr.write("FAILURES:\n")
        for f in failures:
            sys.stderr.write(f"  - {f}\n")
        sys.exit(1)
    print("OK: concurrent daemon stderr lines stayed atomic")


if __name__ == "__main__":
    main()
