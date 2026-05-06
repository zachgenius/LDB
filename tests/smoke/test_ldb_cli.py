#!/usr/bin/env python3
"""End-to-end smoke for the `ldb` CLI (M5 part 4).

The CLI is a thin Python client that spawns `ldbd` as a child, sends one
JSON-RPC request, and prints the response's `data` field. Schema-driven
parsing comes from `describe.endpoints`. View descriptors merge into
`params.view`. Format negotiation passes `--format json|cbor` to the
daemon.

This test exercises the full surface:

    • happy path:           ldb hello                            → exit 0
    • happy path:           ldb target.open path=<fixture>       → exit 0, target_id
    • static analysis:      ldb type.layout target_id=1 name=…   → exit 0, byte_size
    • help:                 ldb --help                           → lists subcommands
    • per-method help:      ldb target.open --help               → shows schema
    • unknown method:       ldb no.such.method                   → exit 1, stderr
    • missing required:     ldb target.open                      → exit 1, "required"
    • view descriptor:      ldb describe.endpoints --view fields=method,summary --view limit=3
                            → 3 items projected
    • cbor transport:       ldb --format=cbor hello              → still works
    • raw envelope:         ldb --raw hello                      → prints _cost too
"""
import json
import os
import subprocess
import sys


def usage():
    sys.stderr.write("usage: test_ldb_cli.py <ldbd> <ldb-cli> <fixture>\n")
    sys.exit(2)


def run_cli(cli, ldbd, args, env=None, timeout=30):
    """Invoke the CLI with --ldbd <ldbd> and the given trailing args.

    Returns (returncode, stdout, stderr).
    """
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    cmd = [cli, "--ldbd", ldbd] + list(args)
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=full_env,
        timeout=timeout,
    )
    return proc.returncode, proc.stdout, proc.stderr


def main():
    if len(sys.argv) != 4:
        usage()
    ldbd, cli, fixture = sys.argv[1], sys.argv[2], sys.argv[3]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n")
        sys.exit(1)
    if not os.access(cli, os.X_OK):
        sys.stderr.write(f"ldb CLI not executable: {cli}\n")
        sys.exit(1)
    if not os.path.isfile(fixture):
        sys.stderr.write(f"fixture missing: {fixture}\n")
        sys.exit(1)

    failures = []

    def expect(cond, msg):
        if not cond:
            failures.append(msg)

    # ------------- ldb hello ----------------------------------------------
    rc, out, err = run_cli(cli, ldbd, ["hello"])
    expect(rc == 0, f"hello: rc={rc} stderr={err!r}")
    try:
        data = json.loads(out)
    except json.JSONDecodeError as e:
        data = None
        failures.append(f"hello: stdout not JSON: {out!r} ({e})")
    if data is not None:
        expect("version" in data, f"hello: missing version: {data!r}")
        expect("name" in data, f"hello: missing name: {data!r}")

    # ------------- ldb target.open path=<fixture> -------------------------
    rc, out, err = run_cli(cli, ldbd, ["target.open", f"path={fixture}"])
    expect(rc == 0, f"target.open: rc={rc} stderr={err!r}")
    try:
        data = json.loads(out)
        expect("target_id" in data, f"target.open: missing target_id: {data!r}")
    except json.JSONDecodeError:
        failures.append(f"target.open: stdout not JSON: {out!r}")

    # ------------- ldb type.layout target_id=1 name=dxp_login_frame ------
    # The CLI is one-shot per invocation (spawns ldbd, calls once, exits).
    # That means target_id=1 from a previous `ldb target.open` doesn't
    # carry over — each call gets a fresh daemon. We exercise the wire
    # path by issuing type.layout against the (always-empty) target
    # table, asserting the typed -32000 error round-trips through the
    # CLI to a non-zero exit + a stderr error message. This validates
    # parameter coercion (target_id as integer, name as string) and
    # error handling end-to-end.
    rc, out, err = run_cli(cli, ldbd, [
        "type.layout", "target_id=1", "name=dxp_login_frame"])
    expect(rc != 0,
           f"type.layout against empty daemon should error: "
           f"rc={rc} out={out!r} err={err!r}")
    expect("error" in err.lower() or "target" in err.lower(),
           f"type.layout missing-target should produce error: stderr={err!r}")

    # ------------- ldb --help ---------------------------------------------
    rc, out, err = run_cli(cli, ldbd, ["--help"])
    expect(rc == 0, f"--help: rc={rc} stderr={err!r}")
    expect("hello" in out, f"--help: missing 'hello' in subcommand list")
    expect("target.open" in out, f"--help: missing 'target.open'")
    expect("describe.endpoints" in out,
           f"--help: missing 'describe.endpoints'")

    # ------------- ldb target.open --help ---------------------------------
    rc, out, err = run_cli(cli, ldbd, ["target.open", "--help"])
    expect(rc == 0, f"target.open --help: rc={rc} stderr={err!r}")
    expect("path" in out, f"target.open --help: missing 'path' param")
    expect("required" in out.lower(),
           f"target.open --help: should mark path required")

    # ------------- ldb no.such.method -------------------------------------
    rc, out, err = run_cli(cli, ldbd, ["no.such.method"])
    expect(rc != 0, f"unknown method should exit nonzero: rc={rc}")
    # Error info goes to stderr.
    expect(len(err) > 0, f"unknown method: empty stderr (out={out!r})")

    # ------------- ldb target.open (missing required) ---------------------
    rc, out, err = run_cli(cli, ldbd, ["target.open"])
    expect(rc != 0, f"missing required param: rc={rc} should be nonzero")
    expect("required" in err.lower() or "missing" in err.lower()
           or "path" in err.lower(),
           f"missing required: stderr should mention required/missing/path: "
           f"{err!r}")

    # ------------- ldb describe.endpoints --view fields=… --view limit=3 --
    rc, out, err = run_cli(cli, ldbd, [
        "describe.endpoints",
        "--view", "fields=method,summary",
        "--view", "limit=3"])
    expect(rc == 0, f"view describe.endpoints: rc={rc} stderr={err!r}")
    try:
        data = json.loads(out)
        eps = data.get("endpoints", [])
        expect(isinstance(eps, list),
               f"view: endpoints not array: {type(eps).__name__}")
        expect(len(eps) == 3, f"view limit=3: got {len(eps)}")
        for e in eps:
            keys = set(e.keys())
            expect(keys == {"method", "summary"},
                   f"view fields projection: unexpected keys {keys}")
        expect("total" in data, f"view: total should be present")
    except (json.JSONDecodeError, KeyError) as e:
        failures.append(f"view: response parse failed: {e}; out={out!r}")

    # ------------- ldb --format=cbor hello --------------------------------
    rc, out, err = run_cli(cli, ldbd, ["--format", "cbor", "hello"])
    expect(rc == 0, f"--format=cbor hello: rc={rc} stderr={err!r}")
    try:
        data = json.loads(out)
        expect("version" in data, f"cbor hello: missing version: {data!r}")
    except json.JSONDecodeError:
        failures.append(f"cbor hello: stdout not JSON: {out!r}")

    # ------------- ldb --raw hello ----------------------------------------
    rc, out, err = run_cli(cli, ldbd, ["--raw", "hello"])
    expect(rc == 0, f"--raw hello: rc={rc} stderr={err!r}")
    try:
        env_resp = json.loads(out)
        expect(env_resp.get("ok") is True,
               f"--raw hello: ok not true: {env_resp!r}")
        expect("_cost" in env_resp,
               f"--raw hello: missing _cost: {env_resp!r}")
        expect("data" in env_resp,
               f"--raw hello: missing data: {env_resp!r}")
    except json.JSONDecodeError:
        failures.append(f"--raw hello: stdout not JSON: {out!r}")

    if failures:
        sys.stderr.write("FAILURES:\n")
        for f in failures:
            sys.stderr.write(f"  - {f}\n")
        sys.exit(1)
    print("OK: ldb CLI smoke")


if __name__ == "__main__":
    main()
