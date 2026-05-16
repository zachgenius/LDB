#!/usr/bin/env python3
"""Phase-4 cleanup C4 adversarial smoke test
(docs/35-field-report-followups.md §3 phase-4 cleanup C4).

LDP / LDPSW / LDXP write to one or two destination registers. The
phase-3/4 resolver's clobber whitelist didn't include any of them, so
a `ldp x8, x9, [sp]` after an `adrp x8, _data@PAGE` left x8 still
tracked. The subsequent ADD through x8 false-matched.

Pattern (see tests/fixtures/asm/xref_ldp_clobber.s):
  ldp_test:
    adrp x8, ldp_data@PAGE
    ldp  x8, x9, [sp]                ; x8/x9 := stack contents
    add  x0, x8, ldp_data@PAGEOFF    ; FALSE POSITIVE pre-C4

Acceptance:
  - xref.addr against `ldp_data` returns ZERO matches in ldp_test.
"""
import json
import os
import subprocess
import sys


def main():
    if len(sys.argv) != 3:
        sys.stderr.write("usage: test_xref_ldp_clobber.py <ldbd> <fixture>\n")
        sys.exit(2)
    ldbd, fixture = sys.argv[1], sys.argv[2]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n"); sys.exit(1)
    if not os.path.isfile(fixture):
        sys.stderr.write(f"fixture missing: {fixture}\n"); sys.exit(1)

    proc = subprocess.Popen(
        [ldbd, "--stdio", "--log-level", "error"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, bufsize=1,
    )

    next_id = [0]
    def call(method, params=None):
        next_id[0] += 1
        rid = f"r{next_id[0]}"
        req = {"jsonrpc": "2.0", "id": rid, "method": method,
               "params": params or {}}
        proc.stdin.write(json.dumps(req) + "\n")
        proc.stdin.flush()
        line = proc.stdout.readline()
        if not line:
            sys.stderr.write("daemon closed stdout: " + proc.stderr.read() + "\n")
            sys.exit(1)
        return json.loads(line)

    try:
        r = call("target.open", {"path": fixture})
        assert r["ok"], r
        tid = r["data"]["target_id"]

        r = call("symbol.find", {"target_id": tid, "name": "ldp_data"})
        assert r["ok"], r
        data_addr = None
        for m in r["data"]["matches"]:
            if m.get("name") == "ldp_data":
                data_addr = m["addr"]
                break
        assert data_addr is not None, f"missing ldp_data: {r}"

        r = call("xref.addr", {"target_id": tid, "addr": data_addr})
        assert r["ok"], r

        bad = [m for m in r["data"]["matches"]
               if m.get("function") == "ldp_test"]
        if bad:
            sys.stderr.write(
                "FAIL: phase-4 C4 false-positive — LDP destination writes "
                "weren't clobbered; the ADD through stale x8 matched "
                f"against {data_addr:#x}. Bad matches: {bad}\n")
            sys.exit(1)

        print(f"xref LDP clobber smoke test PASSED "
              f"(target={data_addr:#x}, ldp_test_hits=0)")
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        proc.wait(timeout=5)


if __name__ == "__main__":
    main()
