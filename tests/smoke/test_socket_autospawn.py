#!/usr/bin/env python3
"""Smoke test: `ldb --socket PATH` auto-spawns a daemon when none is running.

§2 phase-2 of `docs/35-field-report-followups.md`: if the client tries
to connect to a socket whose backing daemon isn't running (ECONNREFUSED
on connect(), or ENOENT on the socket inode), the CLI should fork+exec
`ldbd --listen unix:PATH` as a detached subprocess and retry connect
with a short backoff. The newly-spawned daemon outlives the client
process, so a second `ldb --socket PATH` call reuses it.

Test sequence:
  1. Pick a fresh socket path; no daemon running.
  2. Invoke `ldb --socket $path target.open path=$fixture`.
     Expect: rc=0, target.open responds, daemon auto-spawned.
  3. Invoke a second `ldb --socket $path module.list target_id=$N`.
     Expect: rc=0, the same daemon serves it. target_id from call #1
     is still valid — proof the daemon persisted.
  4. Send SIGTERM to the daemon and assert the socket inode is
     cleaned up. (The daemon is detached, so we have to find its
     pid via the lockfile or `ps`.)
"""
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time


def wait_for_socket(path: str, timeout: float = 8.0) -> bool:
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
        time.sleep(0.1)
    return False


def read_lockfile_pid(lock_path: str) -> int | None:
    try:
        with open(lock_path) as f:
            line = f.readline().strip()
        if line.isdigit():
            return int(line)
    except OSError:
        pass
    return None


def usage():
    sys.stderr.write(
        "usage: test_socket_autospawn.py <ldbd> <ldb-cli> <fixture>\n")
    sys.exit(2)


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

    daemon_pid = None
    with tempfile.TemporaryDirectory() as tmp:
        sock_path = os.path.join(tmp, "ldbd.sock")
        lock_path = sock_path + ".lock"

        # Sanity — no daemon yet.
        expect(not os.path.exists(sock_path),
               f"socket should not exist pre-test: {sock_path}")

        # Set LDB_LDBD_SPAWN to point at our build's ldbd so the CLI
        # picks the right binary without relying on $PATH discovery
        # inside the auto-spawn helper.
        env = dict(os.environ)
        env["LDB_LDBD_SPAWN"] = ldbd

        # First invocation: auto-spawn the daemon, then target.open.
        proc = subprocess.run(
            [cli, "--socket", sock_path, "target.open", f"path={fixture}"],
            capture_output=True,
            text=True,
            timeout=30.0,
            env=env,
        )
        expect(proc.returncode == 0,
               f"first invocation (auto-spawn): rc={proc.returncode} "
               f"stdout={proc.stdout!r} stderr={proc.stderr!r}")

        target_id = None
        try:
            target_id = json.loads(proc.stdout).get("target_id")
        except json.JSONDecodeError:
            failures.append(f"first invocation stdout not JSON: {proc.stdout!r}")

        expect(isinstance(target_id, int),
               f"target.open: missing/non-int target_id: out={proc.stdout!r}")

        # Daemon should still be alive — read its pid from the lockfile.
        if os.path.exists(lock_path):
            daemon_pid = read_lockfile_pid(lock_path)
        expect(daemon_pid is not None,
               f"daemon pid not recoverable from lockfile {lock_path}")

        # Second invocation: reuse the same daemon. target_id must still
        # be valid — proof the daemon survived the first CLI's exit.
        if isinstance(target_id, int):
            proc2 = subprocess.run(
                [cli, "--socket", sock_path,
                 "module.list", f"target_id={target_id}"],
                capture_output=True,
                text=True,
                timeout=30.0,
                env=env,
            )
            expect(proc2.returncode == 0,
                   f"second invocation (reuse daemon): rc={proc2.returncode} "
                   f"stdout={proc2.stdout!r} stderr={proc2.stderr!r}")
            try:
                data = json.loads(proc2.stdout)
                expect("modules" in data,
                       f"second invocation: missing modules: {data!r}")
            except json.JSONDecodeError:
                failures.append(
                    f"second invocation stdout not JSON: {proc2.stdout!r}")

        # Clean up — kill the daemon by pid we recovered from the lockfile.
        if daemon_pid is not None:
            try:
                os.kill(daemon_pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            # Wait for socket to be unlinked.
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                if not os.path.exists(sock_path):
                    break
                time.sleep(0.1)
            expect(not os.path.exists(sock_path),
                   f"daemon should have unlinked socket on shutdown: "
                   f"{sock_path}")

    if failures:
        sys.stderr.write("FAILURES:\n")
        for f in failures:
            sys.stderr.write(f"  - {f}\n")
        sys.exit(1)
    print("OK: client auto-spawned daemon, daemon persisted across "
          "two invocations")


if __name__ == "__main__":
    main()
