#!/usr/bin/env python3
"""End-to-end smoke for the `ldb --repl` interactive mode (post-V1 #10).

The REPL keeps ONE ldbd subprocess alive across many commands. This is
the key win vs the one-shot CLI: target_id (and any other daemon-side
state) from an earlier call is usable in a later call.

Asserts:

  - Two endpoints called in sequence both succeed against the SAME
    daemon. We verify by issuing `target.open path=<fixture>` first,
    capturing the `target_id`, then `module.list target_id=<that>` --
    that target_id must round-trip.
  - `:explain hello` prints something schema-shaped (mentions
    "hello" and "summary" or "params_schema").
  - `:cost` prints a non-empty list of endpoint stats after at least
    one call has been made.
  - `:replay` re-runs the prior call. We issue `hello`, then `:replay`,
    and expect TWO json blobs each with `name: ldbd`.
  - `:quit` exits cleanly with return code 0.

The REPL reads commands line-by-line from its own stdin, so we drive
it by piping a newline-separated command script.
"""
import json
import os
import re
import subprocess
import sys


def usage():
    sys.stderr.write(
        "usage: test_cli_repl.py <ldbd> <ldb-cli> <fixture>\n")
    sys.exit(2)


def run_repl(cli, ldbd, script, timeout=30):
    """Pipe `script` (str) into `cli --ldbd <ldbd> --repl` and return
    (returncode, stdout, stderr)."""
    cmd = [cli, "--ldbd", ldbd, "--repl"]
    proc = subprocess.run(
        cmd,
        input=script,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return proc.returncode, proc.stdout, proc.stderr


def extract_json_blobs(text):
    """Pull every top-level JSON object out of mixed stdout.

    The REPL pretty-prints each response with indent=2 (mirroring
    `--raw`), one object per command. We can't json.loads(text) because
    there are prompts (`> `), :explain output, :cost output interleaved.
    We scan brace-balanced regions at indent 0 instead.
    """
    blobs = []
    i = 0
    n = len(text)
    while i < n:
        if text[i] == "{":
            depth = 0
            start = i
            in_str = False
            esc = False
            while i < n:
                c = text[i]
                if in_str:
                    if esc:
                        esc = False
                    elif c == "\\":
                        esc = True
                    elif c == '"':
                        in_str = False
                else:
                    if c == '"':
                        in_str = True
                    elif c == "{":
                        depth += 1
                    elif c == "}":
                        depth -= 1
                        if depth == 0:
                            i += 1
                            try:
                                blobs.append(json.loads(text[start:i]))
                            except json.JSONDecodeError:
                                pass
                            break
                i += 1
        else:
            i += 1
    return blobs


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

    # Stage 1: persistent daemon — target_id round-trips between calls.
    script = (
        f"target.open path={fixture}\n"
        f"hello\n"
        f":quit\n"
    )
    rc, out, err = run_repl(cli, ldbd, script)
    expect(rc == 0,
           f"persistent-daemon repl: rc={rc} stderr={err!r}")
    blobs = extract_json_blobs(out)
    expect(len(blobs) >= 2,
           f"persistent-daemon repl: expected >=2 JSON blobs, "
           f"got {len(blobs)}: out={out!r}")
    target_id = None
    if blobs:
        # First blob is target.open's response.
        first = blobs[0]
        data = first.get("data") if isinstance(first, dict) else None
        if isinstance(data, dict) and "target_id" in data:
            target_id = data["target_id"]
        else:
            # If we printed --raw envelope, target_id is under data.
            target_id = data.get("target_id") if data else None
        expect(target_id is not None,
               f"target.open didn't yield target_id: {first}")

    # Stage 2: target_id usable in a SECOND call against same daemon.
    if target_id is not None:
        script = (
            f"target.open path={fixture}\n"
            f"module.list target_id={target_id}\n"
            f":quit\n"
        )
        rc, out, err = run_repl(cli, ldbd, script)
        expect(rc == 0,
               f"target_id-roundtrip repl: rc={rc} stderr={err!r}")
        blobs = extract_json_blobs(out)
        expect(len(blobs) >= 2,
               f"target_id-roundtrip: expected 2 JSON blobs, got "
               f"{len(blobs)}: out={out!r}")
        if len(blobs) >= 2:
            mod_resp = blobs[1]
            mod_data = mod_resp.get("data") if isinstance(mod_resp, dict) else None
            mods = mod_data.get("modules", []) if isinstance(mod_data, dict) else []
            expect(isinstance(mods, list) and len(mods) >= 1,
                   f"module.list against persistent target_id={target_id} "
                   f"empty: {mod_resp!r}")

    # Stage 3: :explain hello prints schema-ish.
    script = ":explain hello\n:quit\n"
    rc, out, err = run_repl(cli, ldbd, script)
    expect(rc == 0, f":explain repl: rc={rc} stderr={err!r}")
    expect("hello" in out,
           f":explain hello: stdout missing 'hello': {out!r}")
    expect(
        "params_schema" in out or "summary" in out or "cost_hint" in out,
        f":explain hello: stdout missing schema/summary fields: {out!r}")

    # Stage 4: :cost prints something non-empty after a call has run.
    script = "hello\n:cost\n:quit\n"
    rc, out, err = run_repl(cli, ldbd, script)
    expect(rc == 0, f":cost repl: rc={rc} stderr={err!r}")
    # :cost output should mention `hello` plus at least one of the
    # sample/p50 fields. We assert per-endpoint shape, not exact text.
    expect("hello" in out,
           f":cost: stdout missing endpoint name 'hello': {out!r}")
    expect(re.search(r"(cost_n_samples|n_samples|p50)", out) is not None,
           f":cost: stdout missing cost stats fields: {out!r}")

    # Stage 5: :replay re-runs the prior command.
    script = "hello\n:replay\n:quit\n"
    rc, out, err = run_repl(cli, ldbd, script)
    expect(rc == 0, f":replay repl: rc={rc} stderr={err!r}")
    blobs = extract_json_blobs(out)
    # Two hello responses each containing name=ldbd.
    name_hits = 0
    for b in blobs:
        d = b.get("data") if isinstance(b, dict) else None
        if isinstance(d, dict) and d.get("name") == "ldbd":
            name_hits += 1
    expect(name_hits >= 2,
           f":replay should produce two hello responses, got "
           f"{name_hits} (blobs={len(blobs)}): out={out!r}")

    # Stage 6: :quit exits clean with rc=0 (covered above; assert
    # explicit case with no other input).
    rc, out, err = run_repl(cli, ldbd, ":quit\n")
    expect(rc == 0, f":quit alone: rc={rc} stderr={err!r}")

    # Stage 7: EOF (no input at all) also exits clean.
    rc, out, err = run_repl(cli, ldbd, "")
    expect(rc == 0, f"EOF-only repl: rc={rc} stderr={err!r}")

    if failures:
        sys.stderr.write("FAILURES:\n")
        for f in failures:
            sys.stderr.write(f"  - {f}\n")
        sys.exit(1)
    print("OK: ldb --repl smoke")


if __name__ == "__main__":
    main()
