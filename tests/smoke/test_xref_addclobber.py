#!/usr/bin/env python3
"""Phase-3 adversarial smoke test for the ADRP-pair resolver
(docs/35-field-report-followups.md §3).

Pattern (see tests/fixtures/asm/xref_addclobber.s):
  pattern_addclobber:
    adrp x8, addclobber_data@PAGE
    add  x8, x8, #0x100        ; phase 2: still treats x8 as the page
    ldr  x0, [x8, #0x10]       ; phase-2 buggy target: page+0x10
                                ; phase-3 effective target: page+0x110

Acceptance:
  - xref.addr against `addclobber_data + 0x10` (the false-positive
    target) returns ZERO matches at the LDR address inside
    pattern_addclobber. Phase 2 returns one.
  - xref.addr against `addclobber_data + 0x100` (the ADD's legitimate
    target) returns at least one match attributed to pattern_addclobber.

The second assertion guards against an over-correction: phase 3 still
emits the ADD's match (the ADD resolves an exact target), only the
subsequent LDR using a clobbered register is suppressed.
"""
import json
import os
import subprocess
import sys


def main():
    if len(sys.argv) != 3:
        sys.stderr.write("usage: test_xref_addclobber.py <ldbd> <fixture>\n")
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

        # Look up the data symbol's address. addclobber_data is at the
        # page the ADRP loads; the test exercises +0x10 (phase-2 buggy)
        # and +0x100 (real ADD target).
        r = call("symbol.find", {"target_id": tid, "name": "addclobber_data"})
        assert r["ok"], r
        # symbol.find returns matches array with `addr` field.
        matches = r["data"]["matches"]
        data_addr = None
        for m in matches:
            if m.get("name") == "addclobber_data":
                data_addr = m["addr"]
                break
        assert data_addr is not None, f"addclobber_data not in {matches}"

        # Sanity: the ADD's resolved target.
        real_target = data_addr + 0x100
        # The phase-2 false-positive target.
        false_target = data_addr + 0x10

        # xref.addr against the false-positive target. Phase 2 reports
        # the LDR inside pattern_addclobber. Phase 3 must not.
        r_false = call("xref.addr",
                       {"target_id": tid, "addr": false_target})
        assert r_false["ok"], r_false
        false_matches = r_false["data"]["matches"]
        bad = [m for m in false_matches
               if m.get("function") == "pattern_addclobber"]
        if bad:
            sys.stderr.write(
                "FAIL: phase-3 false positive — xref.addr against "
                f"page+0x10 ({false_target:#x}) returned "
                f"{len(bad)} match(es) in pattern_addclobber: {bad}\n")
            sys.exit(1)

        # xref.addr against the ADD's legitimate target. Phase 3 should
        # still emit the ADD itself as the resolving instruction.
        r_real = call("xref.addr",
                      {"target_id": tid, "addr": real_target})
        assert r_real["ok"], r_real
        real_matches = r_real["data"]["matches"]
        good = [m for m in real_matches
                if m.get("function") == "pattern_addclobber"
                and m.get("mnemonic", "").lower() == "add"]
        if not good:
            sys.stderr.write(
                "FAIL: phase-3 over-correction — xref.addr against "
                f"page+0x100 ({real_target:#x}) returned 0 ADD matches "
                f"in pattern_addclobber. matches={real_matches}\n")
            sys.exit(1)

        print(f"xref ADD-clobber smoke test PASSED "
              f"(data={data_addr:#x}, real_hits={len(good)}, "
              f"false_hits={len(bad)})")
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        proc.wait(timeout=5)


if __name__ == "__main__":
    main()
