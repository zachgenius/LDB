#!/usr/bin/env python3
"""Phase-4 cleanup C3 adversarial smoke test
(docs/35-field-report-followups.md §3 phase-4 cleanup C3).

CSEL writes a non-ADRP value to its destination but doesn't fall in
any of the resolver's explicit-clobber mnemonics. Without clobber-by-
default the destination retains its prior ADRP tracking and a
subsequent LDR through it false-matches.

Pattern (see tests/fixtures/asm/xref_csel.s):
  csel_test:
    adrp x8, csel_data@PAGE
    cmp  w0, #0
    csel x8, x9, x8, gt              ; x8 := (gt ? x9 : x8)
    ldr  x0, [x8, #0x10]             ; FALSE POSITIVE pre-C3

Acceptance:
  - xref.addr against `csel_data + 0x10` returns ZERO matches in
    csel_test. Pre-C3 returns the LDR as a false positive.
"""
import json
import os
import subprocess
import sys


def main():
    if len(sys.argv) != 3:
        sys.stderr.write("usage: test_xref_csel.py <ldbd> <fixture>\n")
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

        r = call("symbol.find", {"target_id": tid, "name": "csel_data"})
        assert r["ok"], r
        data_addr = None
        for m in r["data"]["matches"]:
            if m.get("name") == "csel_data":
                data_addr = m["addr"]
                break
        assert data_addr is not None, f"missing csel_data: {r}"

        false_target = data_addr + 0x10

        r = call("xref.addr", {"target_id": tid, "addr": false_target})
        assert r["ok"], r

        bad = [m for m in r["data"]["matches"]
               if m.get("function") == "csel_test"]
        if bad:
            sys.stderr.write(
                "FAIL: phase-4 C3 false-positive — CSEL destination write "
                "wasn't clobbered; the LDR through stale x8 matched "
                f"against {false_target:#x}. Bad matches: {bad}\n")
            sys.exit(1)

        print(f"xref CSEL clobber smoke test PASSED "
              f"(false_target={false_target:#x}, csel_test_hits=0)")
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        proc.wait(timeout=5)


if __name__ == "__main__":
    main()
