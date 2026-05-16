#!/usr/bin/env python3
"""Phase-3 post-review smoke test for the ADRP-pair resolver
(docs/35-field-report-followups.md §3).

Pattern (see tests/fixtures/asm/xref_subclobber.s):
  pattern_subclobber:
    adrp x8, subclobber_data@PAGE
    sub  x8, x8, #0x100        ; phase-3-old: still treats x8 as page
    ldr  x0, [x8, #0x10]       ; phase-3-old buggy target: page+0x10
                                ; phase-3-new effective target: page-0x100+0x10

Acceptance:
  - xref.addr against `subclobber_data + 0x10` (the false-positive
    target) returns ZERO matches at the LDR address inside
    pattern_subclobber. The original phase-3 patch only clobbered on
    ADD; the SUB silently slipped through.

SUB+ADRP doesn't have a legitimate "compute target via subtraction"
pattern in real compiler output (compilers use ADD with a signed
immediate or pre-compute via a different scheme). So unlike ADD,
SUB has only the clobber half — no match-emit. The test only
asserts the false-positive is suppressed; it does not assert any
new match was emitted.
"""
import json
import os
import subprocess
import sys


def main():
    if len(sys.argv) != 3:
        sys.stderr.write("usage: test_xref_subclobber.py <ldbd> <fixture>\n")
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

        r = call("symbol.find", {"target_id": tid, "name": "subclobber_data"})
        assert r["ok"], r
        data_addr = None
        for m in r["data"]["matches"]:
            if m.get("name") == "subclobber_data":
                data_addr = m["addr"]
                break
        assert data_addr is not None, f"missing subclobber_data: {r}"

        # The phase-3-old false-positive target. The SUB makes the LDR's
        # real effective address (page - 0x100 + 0x10) NOT equal to
        # data_addr + 0x10; phase-3-new must clear adrp_regs[x8] on the
        # SUB so the LDR doesn't match this target.
        false_target = data_addr + 0x10

        r_false = call("xref.addr",
                       {"target_id": tid, "addr": false_target})
        assert r_false["ok"], r_false
        bad = [m for m in r_false["data"]["matches"]
               if m.get("function") == "pattern_subclobber"]
        if bad:
            sys.stderr.write(
                "FAIL: SUB-clobber regression — xref.addr against "
                f"{false_target:#x} returned {len(bad)} match(es) in "
                f"pattern_subclobber (x8 should be cleared after SUB): "
                f"{bad}\n")
            sys.exit(1)

        print(f"xref SUB-clobber smoke test PASSED "
              f"(data={data_addr:#x}, false_hits={len(bad)})")
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        proc.wait(timeout=5)


if __name__ == "__main__":
    main()
