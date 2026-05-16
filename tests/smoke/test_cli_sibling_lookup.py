#!/usr/bin/env python3
"""Smoke for the `ldb` CLI sibling-lookup heuristic.

Background: `tools/ldb/ldb` and `<repo>/build/bin/ldbd` are siblings in
the in-tree dev layout but neither is on `$PATH`. Before this change,
running `ldb <subcommand>` from any CWD other than the repo root failed
with "ldbd not found" — the user had to pass `--ldbd PATH` on every
invocation. See `docs/35-field-report-followups.md` §1.

This test pins the new precedence:

    1. --ldbd PATH                          (explicit)
    2. shutil.which("ldbd")                 ($PATH lookup)
    3. <script-dir>/../../build/bin/ldbd    (sibling from __file__) ← NEW
    4. ./build/bin/ldbd                     (CWD-relative fallback)

We exercise:

    • sibling lookup wins when $PATH has no ldbd and CWD is unrelated
      → `ldb hello` succeeds.
    • --ldbd PATH overrides the sibling (precedence #1 > #3) → fail-fast
      on a non-executable path; the sibling-lookup heuristic must not
      paper over a bad explicit override.
"""
import json
import os
import subprocess
import sys
import tempfile


def usage():
    sys.stderr.write(
        "usage: test_cli_sibling_lookup.py <ldbd> <ldb-cli>\n"
        "  <ldbd>:    the in-tree-built ldbd (used only for sanity)\n"
        "  <ldb-cli>: the ldb script under <repo>/tools/ldb/ldb\n")
    sys.exit(2)


def scrubbed_env():
    """Return an env dict with $PATH stripped of any dir that contains ldbd.

    We can't just unset PATH entirely — python3 itself is on PATH on
    most CI machines (the test runner spawns python3 implicitly). We
    keep dirs that don't have an `ldbd` executable.
    """
    env = dict(os.environ)
    path = env.get("PATH", "")
    keep = []
    for d in path.split(os.pathsep):
        if not d:
            continue
        cand = os.path.join(d, "ldbd")
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            continue  # drop this dir from PATH
        keep.append(d)
    env["PATH"] = os.pathsep.join(keep)
    return env


def main():
    if len(sys.argv) != 3:
        usage()
    ldbd, cli = sys.argv[1], sys.argv[2]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n")
        sys.exit(1)
    if not os.access(cli, os.X_OK):
        sys.stderr.write(f"ldb CLI not executable: {cli}\n")
        sys.exit(1)

    # Derive what the script's sibling lookup is expected to find. The
    # script lives at <repo>/tools/ldb/ldb; two parents up is <repo>;
    # then build/bin/ldbd.
    expected_sibling = os.path.normpath(
        os.path.join(os.path.dirname(cli), "..", "..", "build", "bin", "ldbd"))
    if not os.access(expected_sibling, os.X_OK):
        sys.stderr.write(
            f"precondition failed: no built ldbd at expected sibling "
            f"path {expected_sibling!r}. Run `cmake --build build` first.\n")
        sys.exit(1)

    failures = []

    def expect(cond, msg):
        if not cond:
            failures.append(msg)

    env = scrubbed_env()
    # Belt and braces: explicitly drop any LDB_* env that could route
    # around the in-tree path (e.g. LDB_SSH_TARGET would force --ssh).
    for k in list(env.keys()):
        if k.startswith("LDB_"):
            del env[k]

    # --- Test 1: sibling lookup. ----------------------------------------
    # CWD = an unrelated tempdir (no ./build/bin/ldbd in it).
    # PATH = scrubbed of any ldbd.
    # No --ldbd flag.
    # Expectation: CLI still runs `hello` against the sibling daemon.
    with tempfile.TemporaryDirectory() as cwd:
        proc = subprocess.run(
            [cli, "hello"],
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
    expect(
        proc.returncode == 0,
        f"sibling lookup: rc={proc.returncode} "
        f"stdout={proc.stdout!r} stderr={proc.stderr!r}")
    if proc.returncode == 0:
        try:
            data = json.loads(proc.stdout)
            expect("version" in data,
                   f"sibling lookup: missing version in {data!r}")
            expect("name" in data,
                   f"sibling lookup: missing name in {data!r}")
        except json.JSONDecodeError as e:
            failures.append(
                f"sibling lookup: stdout not JSON: {proc.stdout!r} ({e})")

    # --- Test 2: --ldbd PATH precedence is preserved. --------------------
    # If the user passes --ldbd with a non-executable path, the CLI must
    # FAIL FAST — not silently fall through to the sibling daemon. This
    # pins precedence #1 ahead of #3.
    with tempfile.TemporaryDirectory() as cwd:
        bogus = os.path.join(cwd, "definitely-not-ldbd")
        # Create a non-executable file so the path "exists" but is unrunnable.
        with open(bogus, "w") as f:
            f.write("not executable\n")
        # No chmod +x — os.access(bogus, X_OK) is False.
        proc = subprocess.run(
            [cli, "--ldbd", bogus, "hello"],
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
    expect(
        proc.returncode != 0,
        f"--ldbd precedence: should fail-fast on non-executable, "
        f"got rc={proc.returncode} stdout={proc.stdout!r} "
        f"stderr={proc.stderr!r}")
    expect(
        "not executable" in proc.stderr.lower()
        or "ldbd" in proc.stderr.lower(),
        f"--ldbd precedence: stderr should mention the bad path: "
        f"{proc.stderr!r}")

    if failures:
        sys.stderr.write("FAILURES:\n")
        for f in failures:
            sys.stderr.write(f"  - {f}\n")
        sys.exit(1)
    print("OK: ldb CLI sibling lookup")


if __name__ == "__main__":
    main()
