#!/usr/bin/env python3
"""Smoke test: `ldbd --listen unix:PATH` enforces uid-only permissions.

§2 phase 1 of `docs/35-field-report-followups.md` promises:
  * Socket file mode 0600.
  * If the daemon creates the parent directory, mode 0700.

This is the only access control in phase 1 (no token auth, no cross-
user access). A regression here silently widens the daemon's
exposure, so it gets its own pinned test.

Post-review hardening additions:
  * Symlinked parent directory must be refused (H2): an attacker who
    pre-creates ${PATH}'s parent as a symlink to a sensitive dir
    must not trick the daemon into bind()ing inside it.
  * Symlinked lock file must be refused (H1): pre-creating
    ${PATH}.lock as a symlink to an unrelated file must not let the
    daemon's ftruncate/pwrite corrupt the symlink target.
  * Relative `--listen unix:PATH` must be refused (M3): we only
    accept absolute paths so the operator can't accidentally bind a
    socket in a CWD they don't expect.
"""
import os
import select
import signal
import socket
import stat
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
                err = read_stderr_nonblocking(daemon)
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
                err = read_stderr_nonblocking(daemon)
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

    # Scenario C: relative `--listen unix:PATH` must be refused (M3).
    # The daemon should exit with a clear stderr message; we don't
    # care about the exact path, only that startup fails fast and
    # mentions absolute.
    relative_run = subprocess.run(
        [ldbd, "--listen", "unix:relative/path.sock",
         "--log-level", "error"],
        capture_output=True,
        text=True,
        timeout=5.0,
    )
    expect(relative_run.returncode != 0,
           f"relative --listen path: should fail, rc="
           f"{relative_run.returncode} stderr={relative_run.stderr!r}")
    expect("absolute" in relative_run.stderr.lower(),
           f"relative --listen path: stderr should mention 'absolute': "
           f"{relative_run.stderr!r}")

    # Scenario D: parent of socket path is a symlink (H2). Daemon
    # must refuse — current code follows the symlink and bind()s
    # inside whatever the symlink points to.
    with tempfile.TemporaryDirectory() as outer:
        real = os.path.join(outer, "realdir")
        link = os.path.join(outer, "linkdir")
        os.mkdir(real, 0o700)
        os.symlink(real, link)
        sock = os.path.join(link, "ldbd.sock")
        run = subprocess.run(
            [ldbd, "--listen", f"unix:{sock}", "--log-level", "error"],
            capture_output=True,
            text=True,
            timeout=5.0,
        )
        expect(run.returncode != 0,
               f"symlinked parent: should fail, rc={run.returncode} "
               f"stderr={run.stderr!r}")
        # Don't pin exact wording — just that the error explains.
        expect("symlink" in run.stderr.lower()
               or "refus" in run.stderr.lower(),
               f"symlinked parent: stderr should explain refusal: "
               f"{run.stderr!r}")

    # Scenario E: lockfile is a pre-existing symlink (H1). The
    # daemon must refuse to open the lockfile through a symlink —
    # otherwise ftruncate+pwrite of the holder pid would corrupt
    # the symlink target.
    with tempfile.TemporaryDirectory() as tmp:
        sock = os.path.join(tmp, "ldbd.sock")
        lock = sock + ".lock"
        target = os.path.join(tmp, "victim")
        with open(target, "w") as f:
            f.write("DO NOT OVERWRITE\n")
        os.symlink(target, lock)
        run = subprocess.run(
            [ldbd, "--listen", f"unix:{sock}", "--log-level", "error"],
            capture_output=True,
            text=True,
            timeout=5.0,
        )
        expect(run.returncode != 0,
               f"symlinked lockfile: should fail, rc={run.returncode} "
               f"stderr={run.stderr!r}")
        # Victim file must be untouched.
        with open(target) as f:
            body = f.read()
        expect(body == "DO NOT OVERWRITE\n",
               f"symlinked lockfile: victim was modified: {body!r}")

    if failures:
        sys.stderr.write("FAILURES:\n")
        for f in failures:
            sys.stderr.write(f"  - {f}\n")
        sys.exit(1)
    print("OK: socket / parent-dir permissions + symlink + abs-path "
          "guards enforced")


if __name__ == "__main__":
    main()
