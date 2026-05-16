#!/usr/bin/env python3
"""Phase-3 post-review smoke test for the ADRP-pair resolver
(docs/35-field-report-followups.md §3 improvement 4).

Pattern (see tests/fixtures/asm/xref_str.s):

  pattern_str_through_adrp:
    adrp x8, str_data@PAGE
    str  w0, [x8, #0x10]

  pattern_stp_through_adrp:
    adrp x8, str_data@PAGE
    stp  x0, x1, [x8, #0x10]

  pattern_strb_through_adrp:
    adrp x8, str_data@PAGE
    strb w0, [x8, #0x10]

Acceptance:
  - xref.addr against `str_data + 0x10` returns at least one match
    in each of the three pattern_*_through_adrp functions. Phase-3-
    old recognised only LDR-family consumers and emitted nothing
    for STR/STP/STRB — a real "what writes to this global" gap.
"""
import json
import os
import subprocess
import sys


def main():
    if len(sys.argv) != 3:
        sys.stderr.write("usage: test_xref_str.py <ldbd> <fixture>\n")
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

        r = call("symbol.find", {"target_id": tid, "name": "str_data"})
        assert r["ok"], r
        data_addr = None
        for m in r["data"]["matches"]:
            if m.get("name") == "str_data":
                data_addr = m["addr"]
                break
        assert data_addr is not None, f"missing str_data: {r}"

        target = data_addr + 0x10
        r = call("xref.addr", {"target_id": tid, "addr": target})
        assert r["ok"], r
        matches = r["data"]["matches"]

        wanted = {
            "pattern_str_through_adrp":  ("str", False),
            "pattern_stp_through_adrp":  ("stp", False),
            "pattern_strb_through_adrp": ("strb", False),
        }
        for m in matches:
            fn = m.get("function")
            if fn in wanted:
                expected_mnem, _ = wanted[fn]
                got_mnem = m.get("mnemonic", "").lower()
                if got_mnem == expected_mnem:
                    wanted[fn] = (expected_mnem, True)

        missing = [fn for fn, (_, ok) in wanted.items() if not ok]
        if missing:
            sys.stderr.write(
                "FAIL: STR/STP/STRB through ADRP not surfaced — "
                f"xref.addr against {target:#x} missing matches in: "
                f"{missing}. all matches={matches}\n")
            sys.exit(1)

        print(f"xref STR-family smoke test PASSED "
              f"(data={data_addr:#x}, hits={len(matches)})")
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        proc.wait(timeout=5)


if __name__ == "__main__":
    main()
