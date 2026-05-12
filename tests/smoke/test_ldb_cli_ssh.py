#!/usr/bin/env python3
"""Smoke test for v1.4 #11 — ssh-remote daemon mode on the `ldb` CLI.

The CLI's `--ssh` flag turns the daemon spawn into an ssh-launched
stdio subprocess. We don't need a real remote: a shell shim on PATH
stands in for `ssh`, either recording its argv (composition test) or
exec'ing the local ldbd binary (end-to-end test).

Cases:
  1. argv composition with host, port, --ssh-key, --ssh-options,
     --ldbd-path  →  shim records argv, we assert -p/-i/-o ordering
     and the trailing `--` boundary.
  2. LDB_SSH_TARGET env-variable override  →  no --ssh flag, just env;
     argv must still come from the shim.
  3. --ssh and --ldbd mutually exclusive  →  rc=2 + stderr message.
  4. End-to-end JSON-RPC round-trip via a shim that exec's local ldbd
     (proves the spec threading through fetch_catalog + do_rpc works).
"""
import json
import os
import shlex
import subprocess
import sys
import tempfile


def usage():
    sys.stderr.write("usage: test_ldb_cli_ssh.py <ldbd> <ldb-cli>\n")
    sys.exit(2)


def write_shim_record_argv(shim_dir: str, argv_log: str) -> None:
    """Fake `ssh` that records its argv to a file and exits 0.

    Exiting before speaking JSON-RPC means the CLI will surface an
    I/O / EOF error — that's expected; we're asserting on argv only.
    """
    shim = os.path.join(shim_dir, "ssh")
    with open(shim, "w") as f:
        f.write(
            "#!/bin/sh\n"
            f"printf '%s\\n' \"$@\" > {shlex.quote(argv_log)}\n"
            "exit 0\n"
        )
    os.chmod(shim, 0o755)


def write_shim_exec_local(shim_dir: str, real_ldbd: str) -> None:
    """Fake `ssh` that exec's the local ldbd binary in stdio mode.

    All ssh-side args are dropped; the test verifies the CLI's wire
    transport is transparent, not whatever shell would do with the
    trailing `--` command.
    """
    shim = os.path.join(shim_dir, "ssh")
    with open(shim, "w") as f:
        f.write(
            "#!/bin/sh\n"
            f"exec {shlex.quote(real_ldbd)} "
            "--stdio --format json --log-level error\n"
        )
    os.chmod(shim, 0o755)


def run_cli(cli, args, shim_dir, extra_env=None, timeout=15):
    env = dict(os.environ)
    env["PATH"] = shim_dir + os.pathsep + env.get("PATH", "")
    # Make sure LDB_SSH_TARGET from the surrounding shell doesn't leak in
    # except where a case sets it explicitly.
    env.pop("LDB_SSH_TARGET", None)
    if extra_env:
        env.update(extra_env)
    proc = subprocess.run(
        [cli] + list(args),
        capture_output=True, text=True, env=env, timeout=timeout,
    )
    return proc.returncode, proc.stdout, proc.stderr


def read_argv_log(path: str) -> list[str]:
    with open(path) as f:
        return [ln for ln in f.read().split("\n") if ln]


def main():
    if len(sys.argv) != 3:
        usage()
    ldbd, cli = sys.argv[1], sys.argv[2]
    for path, name in ((ldbd, "ldbd"), (cli, "ldb CLI")):
        if not os.access(path, os.X_OK):
            sys.stderr.write(f"{name} not executable: {path}\n")
            sys.exit(1)

    failures: list[str] = []

    def expect(cond, msg):
        if not cond:
            failures.append(msg)

    with tempfile.TemporaryDirectory() as td:
        # --- Case 1: argv composition --------------------------------
        rec_dir = os.path.join(td, "rec")
        os.makedirs(rec_dir)
        argv_log = os.path.join(td, "argv.log")
        write_shim_record_argv(rec_dir, argv_log)

        rc, out, err = run_cli(
            cli,
            ["--ssh", "alice@host.example:2222",
             "--ssh-key", "/tmp/key",
             "--ssh-options", "-o ProxyJump=bastion",
             "--ldbd-path", "/opt/ldb/bin/ldbd",
             "hello"],
            rec_dir,
        )
        expect(os.path.isfile(argv_log),
               f"shim didn't fire (rc={rc} err={err!r})")
        if os.path.isfile(argv_log):
            got = read_argv_log(argv_log)
            # Port: -p 2222 pair.
            expect("-p" in got and "2222" in got,
                   f"argv missing -p / port 2222: {got!r}")
            # Key: -i /tmp/key + IdentitiesOnly=yes sentinel.
            expect("-i" in got and "/tmp/key" in got,
                   f"argv missing -i / key: {got!r}")
            expect("IdentitiesOnly=yes" in got,
                   f"argv missing IdentitiesOnly=yes (paired with -i): "
                   f"{got!r}")
            # ssh-options parsed via shlex → "-o" and "ProxyJump=bastion".
            expect(got.count("-o") >= 2,
                   f"argv should carry both IdentitiesOnly and ProxyJump "
                   f"-o pairs: {got!r}")
            expect("ProxyJump=bastion" in got,
                   f"argv missing raw -o options value: {got!r}")
            # Host as user@host (port stripped).
            expect("alice@host.example" in got,
                   f"argv missing host (sans port): {got!r}")
            expect("host.example:2222" not in got,
                   f"port should have been stripped from host arg: {got!r}")
            # Trailing -- + remote ldbd + stdio args.
            expect("--" in got,
                   f"argv missing `--` separator: {got!r}")
            expect("/opt/ldb/bin/ldbd" in got,
                   f"argv missing remote ldbd path override: {got!r}")
            expect("--stdio" in got, f"argv missing --stdio: {got!r}")
            expect("--format" in got and "json" in got,
                   f"argv missing --format json: {got!r}")
            expect("--log-level" in got and "error" in got,
                   f"argv missing --log-level error: {got!r}")
            # Order check: everything before `--` is ssh-side, everything
            # after is the remote command.
            dash_idx = got.index("--")
            expect("alice@host.example" in got[:dash_idx],
                   f"host should be before `--`: {got!r}")
            expect("/opt/ldb/bin/ldbd" in got[dash_idx + 1:],
                   f"remote ldbd should be after `--`: {got!r}")

        # --- Case 2: LDB_SSH_TARGET env override ---------------------
        if os.path.isfile(argv_log):
            os.remove(argv_log)
        rc, out, err = run_cli(
            cli, ["hello"], rec_dir,
            extra_env={"LDB_SSH_TARGET": "bob@other.host"},
        )
        expect(os.path.isfile(argv_log),
               f"env-only ssh didn't trigger shim (rc={rc} err={err!r})")
        if os.path.isfile(argv_log):
            got = read_argv_log(argv_log)
            expect("bob@other.host" in got,
                   f"env-override host missing from argv: {got!r}")
            # No --ssh-key was passed and no port given.
            expect("-i" not in got,
                   f"env-only path shouldn't carry -i: {got!r}")
            expect("-p" not in got,
                   f"env-only path shouldn't carry -p: {got!r}")

        # --- Case 3: --ssh and --ldbd mutually exclusive -------------
        rc, out, err = run_cli(
            cli, ["--ssh", "x@y", "--ldbd", ldbd, "hello"], rec_dir,
        )
        expect(rc == 2,
               f"mutual-exclusion should exit rc=2, got rc={rc} "
               f"out={out!r} err={err!r}")
        expect("mutually exclusive" in err.lower(),
               f"mutual-exclusion stderr lacks the message: {err!r}")

        # --- Case 4: end-to-end via exec-local shim ------------------
        exec_dir = os.path.join(td, "exec")
        os.makedirs(exec_dir)
        write_shim_exec_local(exec_dir, ldbd)
        rc, out, err = run_cli(
            cli, ["--ssh", "any@where", "hello"], exec_dir, timeout=30)
        expect(rc == 0,
               f"end-to-end hello rc={rc} out={out!r} err={err!r}")
        if rc == 0:
            try:
                data = json.loads(out)
                expect(data.get("name") == "ldbd",
                       f"end-to-end hello data: {data!r}")
                expect("version" in data,
                       f"end-to-end hello missing version: {data!r}")
            except json.JSONDecodeError as e:
                failures.append(
                    f"end-to-end hello stdout not JSON: {out!r} ({e})")

    if failures:
        sys.stderr.write("FAILURES:\n")
        for f in failures:
            sys.stderr.write(f"  - {f}\n")
        sys.exit(1)
    print("OK: ldb --ssh smoke")


if __name__ == "__main__":
    main()
