#!/usr/bin/env python3
"""Smoke test: bad `$LDB_LDBD_SPAWN` is rejected before the 3s retry.

§2 phase-2 post-review I5: `_resolve_autospawn_ldbd()` used to accept
any X_OK path in `$LDB_LDBD_SPAWN`. A mistyped path that happened to
land on a real executable (e.g. `/usr/bin/yes`) would spawn that
binary instead of ldbd; the spawned child would never bind the
socket and the client would burn ~3s of connect retries before
surfacing "auto-spawned ldbd never began accepting on <path>" — a
diagnostic that gives the operator no hint that their env var was
wrong.

Post-fix: the resolver runs `<path> --version` with a 2s timeout and
checks the output contains the literal "ldbd". A binary that exits
0 but produces unrelated output (`/usr/bin/yes` exits non-zero on
SIGPIPE; `/bin/echo --version` exits 0 with output that doesn't
mention ldbd) is rejected — the resolver logs a diagnostic to
stderr and falls through to the next resolution step.

Test sequence:
  1. Pick a real-but-wrong executable for `$LDB_LDBD_SPAWN`. We use
     `/bin/echo` because it's POSIX-universal, exits 0, and prints
     something that doesn't contain "ldbd". (We can't use
     `/usr/bin/yes` because its exit code on SIGPIPE from the probe
     is non-zero anyway; `_looks_like_ldbd` rejects on rc!=0 too,
     but that path is a weaker test of the substring check.)
  2. Scrub `$PATH` so the resolver can't fall through to a
     `which("ldbd")`. With both the env var override and the PATH
     lookup gone, only the sibling-of-ldb heuristic remains.
  3. Run the script from a temp CWD outside the repo and pass the
     CLI by absolute path. The sibling heuristic anchors on
     `__file__` so it will still find the build-tree ldbd — that's
     the BENIGN fallthrough we want: the bad env var is reported
     on stderr and the CLI keeps working.
  4. Assert: the CLI invocation succeeds (rc=0), the stderr
     contains "LDB_LDBD_SPAWN" and "does not look like ldbd",
     and the auto-spawn diagnostic is emitted BEFORE any
     "never began accepting" line (i.e. we did not burn the 3s
     retry path).
"""
import os
import subprocess
import sys
import tempfile
import time


def usage():
    sys.stderr.write(
        "usage: test_socket_autospawn_validates_binary.py "
        "<ldbd> <ldb-cli> <fixture>\n")
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

    # `/bin/echo` is POSIX-universal and exits 0 with output that
    # doesn't contain "ldbd". A robust choice for the "real executable
    # that isn't ldbd" slot. /bin/echo also exists on macOS and Linux.
    bad_binary = "/bin/echo"
    if not os.access(bad_binary, os.X_OK):
        sys.stderr.write(
            f"{bad_binary} not available on this host; skipping\n")
        sys.exit(0)

    failures = []

    def expect(cond, msg):
        if not cond:
            failures.append(msg)

    with tempfile.TemporaryDirectory() as tmp:
        sock_path = os.path.join(tmp, "ldbd.sock")

        # Pin LDB_LDBD_SPAWN to the wrong-but-executable binary.
        # Strip $PATH down to nothing useful so `which("ldbd")` can't
        # rescue. The sibling-of-ldb fallback will still find the
        # build-tree ldbd via `__file__` anchoring — that's the
        # graceful-degradation path we want to validate.
        env = dict(os.environ)
        env["LDB_LDBD_SPAWN"] = bad_binary
        # Construct a minimal $PATH that contains python3 (for the
        # CLI's shebang via `env`) but no ldbd. We can't drop $PATH
        # entirely because `env python3` needs to find python3, and
        # we can't keep the full $PATH because a developer's local
        # `ldbd` on $PATH would short-circuit the bad-binary test.
        # The interpreter's bin dir is sufficient for python3; we
        # add /usr/bin so coreutils stays available for subprocess
        # calls inside the CLI.
        python_bindir = os.path.dirname(sys.executable)
        env["PATH"] = f"{python_bindir}:/usr/bin:/bin"

        # Measure wall-clock duration. The pre-fix path took ~3s because
        # of the connect-retry loop; post-fix should be sub-second
        # (just the spawn + bind time of the real ldbd via sibling).
        start = time.monotonic()
        proc = subprocess.run(
            [cli, "--socket", sock_path, "target.open", f"path={fixture}"],
            capture_output=True,
            text=True,
            timeout=30.0,
            env=env,
            cwd=tmp,  # outside the repo so CWD-relative fallback can't help
        )
        elapsed = time.monotonic() - start

        expect(proc.returncode == 0,
               f"CLI should still succeed via sibling fallback; "
               f"rc={proc.returncode} stdout={proc.stdout!r} "
               f"stderr={proc.stderr!r}")

        expect("LDB_LDBD_SPAWN" in proc.stderr,
               f"stderr should mention LDB_LDBD_SPAWN; got: {proc.stderr!r}")
        expect("does not look like ldbd" in proc.stderr,
               f"stderr should explain the rejection reason; "
               f"got: {proc.stderr!r}")
        expect("never began accepting" not in proc.stderr,
               f"should NOT have burned the 3s retry path; "
               f"got: {proc.stderr!r}")

        # Clean up: kill any daemon the sibling-fallback spawned.
        # The auto-spawn writes a lockfile next to the socket; if
        # we can read it, send SIGTERM. Best-effort — the daemon
        # is detached, so we can't reap it via subprocess.
        lock_path = sock_path + ".lock"
        if os.path.exists(lock_path):
            try:
                with open(lock_path) as f:
                    pid = int(f.readline().strip())
                os.kill(pid, 15)  # SIGTERM
            except (OSError, ValueError):
                pass

        # Belt-and-braces: pin the timing claim. Anything under 2s
        # confirms we didn't enter the retry loop; the bad-binary
        # path should fail at resolve-time, not at connect-time.
        # Use 2.5s as a generous upper bound (sibling-spawned daemon
        # bind time is well under 1s).
        expect(elapsed < 2.5,
               f"resolution should fail-fast; took {elapsed:.2f}s "
               f"(pre-fix took ~3s burning connect retries)")

    if failures:
        sys.stderr.write("FAILURES:\n")
        for f in failures:
            sys.stderr.write(f"  - {f}\n")
        sys.exit(1)
    print("OK: bad LDB_LDBD_SPAWN rejected at resolve-time with clear "
          "diagnostic; CLI succeeded via sibling fallback")


if __name__ == "__main__":
    main()
