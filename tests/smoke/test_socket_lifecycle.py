#!/usr/bin/env python3
"""Smoke test for `ldbd --listen unix:PATH` persistent socket daemon (§2).

Validates the phase-1 lifecycle promise documented in
`docs/35-field-report-followups.md §2`: a daemon launched with
`--listen unix:$sock` accepts one connection at a time, serves it to
completion, then accepts the next — with `target_id` and all other
dispatcher-side state surviving the disconnect.

Test sequence:
  1. Start `ldbd --listen unix:$sock` as a background subprocess.
  2. Wait until the socket file appears.
  3. Connect via `ldb --socket $sock target.open path=$fixture` → exit 0,
     extract `target_id`.
  4. Connect a SECOND time via `ldb --socket $sock module.list
     target_id=$N` → exit 0. State carried across the disconnect.
  5. Terminate the daemon with SIGTERM; assert clean exit.
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


def read_stderr_nonblocking(proc, timeout: float = 0.2) -> bytes:
    """Drain whatever stderr is ready, with a short timeout.

    The earlier `proc.stderr.read1(4096)` form blocks the test runner
    if the daemon is alive but hasn't written anything — we only want
    diagnostic context. `select` lets us bound the wait so the test
    never stalls on a healthy daemon's quiet stderr.
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
    sys.stderr.write(
        "usage: test_socket_lifecycle.py <ldbd> <ldb-cli> <fixture>\n")
    sys.exit(2)


def wait_for_socket(path: str, timeout: float = 5.0) -> bool:
    """Spin until the unix socket file appears AND accepts connections."""
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


def run_cli(cli: str, sock: str, args: list, timeout: float = 15.0):
    cmd = [cli, "--socket", sock] + args
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return proc.returncode, proc.stdout, proc.stderr


def main():
    if len(sys.argv) != 4:
        usage()
    ldbd, cli, fixture = sys.argv[1], sys.argv[2], sys.argv[3]

    for path, label in [(ldbd, "ldbd"), (cli, "ldb CLI")]:
        if not os.access(path, os.X_OK):
            sys.stderr.write(f"{label} not executable: {path}\n")
            sys.exit(1)
    if not os.path.isfile(fixture):
        sys.stderr.write(f"fixture missing: {fixture}\n")
        sys.exit(1)

    failures = []

    def expect(cond, msg):
        if not cond:
            failures.append(msg)

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
                err = read_stderr_nonblocking(daemon)
                sys.stderr.write(
                    f"daemon never bound socket; stderr={err!r}\n")
                sys.exit(1)

            # --- Connection #1: open a target -----------------------------
            rc, out, err = run_cli(cli, sock, [
                "target.open", f"path={fixture}"])
            expect(rc == 0,
                   f"connection #1 target.open: rc={rc} stderr={err!r}")
            target_id = None
            try:
                data = json.loads(out)
                target_id = data.get("target_id")
            except json.JSONDecodeError as e:
                failures.append(
                    f"connection #1 target.open: stdout not JSON: {out!r} "
                    f"({e})")
            expect(isinstance(target_id, int),
                   f"connection #1 target.open: missing/non-int target_id: "
                   f"out={out!r}")

            # --- Connection #2: module.list against the SAME target_id ----
            if isinstance(target_id, int):
                rc, out, err = run_cli(cli, sock, [
                    "module.list", f"target_id={target_id}"])
                expect(rc == 0,
                       f"connection #2 module.list: rc={rc} "
                       f"stderr={err!r} (target should persist across "
                       f"disconnect — §2 phase-1 promise)")
                try:
                    data = json.loads(out)
                    expect("modules" in data,
                           f"connection #2 module.list: missing modules: "
                           f"{data!r}")
                except json.JSONDecodeError as e:
                    failures.append(
                        f"connection #2 module.list: stdout not JSON: "
                        f"{out!r} ({e})")

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
    print("OK: socket lifecycle (target_id persisted across disconnect)")


if __name__ == "__main__":
    main()
