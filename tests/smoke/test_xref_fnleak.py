#!/usr/bin/env python3
"""Phase-3 adversarial smoke test for the ADRP-pair resolver
(docs/35-field-report-followups.md §3).

Pattern (see tests/fixtures/asm/xref_fnleak.s):
  pattern_fnleak_a:
    adrp x8, fnleak_data_a@PAGE
    ldr  x0, [x8, fnleak_data_a@PAGEOFF]   ; legitimate load
    ret
  pattern_fnleak_b:
    ldr  x0, [x8, #0x10]   ; x8 undefined; phase 2 resolves through
                            ; the leaked adrp_regs from pattern_fnleak_a.

Acceptance:
  - xref.addr against `fnleak_data_a + 0x10` returns ZERO matches in
    pattern_fnleak_b. Phase 2 returns one (the LDR).
  - xref.addr against `fnleak_data_a` itself still returns at least
    one match in pattern_fnleak_a (the legitimate LDR is intact).
"""
import json
import os
import subprocess
import sys


def main():
    if len(sys.argv) != 3:
        sys.stderr.write("usage: test_xref_fnleak.py <ldbd> <fixture>\n")
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

        r = call("symbol.find", {"target_id": tid, "name": "fnleak_data_a"})
        assert r["ok"], r
        data_addr = None
        for m in r["data"]["matches"]:
            if m.get("name") == "fnleak_data_a":
                data_addr = m["addr"]
                break
        assert data_addr is not None, f"missing fnleak_data_a: {r}"

        # The false-positive target produced by the cross-function leak.
        false_target = data_addr + 0x10

        r_false = call("xref.addr",
                       {"target_id": tid, "addr": false_target})
        assert r_false["ok"], r_false
        bad = [m for m in r_false["data"]["matches"]
               if m.get("function") == "pattern_fnleak_b"]
        if bad:
            sys.stderr.write(
                "FAIL: phase-3 cross-function leak — xref.addr against "
                f"{false_target:#x} returned {len(bad)} match(es) in "
                f"pattern_fnleak_b (stale adrp_regs[x8] leaked): {bad}\n")
            sys.exit(1)

        # The legitimate xref must still be present.
        r_real = call("xref.addr",
                      {"target_id": tid, "addr": data_addr})
        assert r_real["ok"], r_real
        good = [m for m in r_real["data"]["matches"]
                if m.get("function") == "pattern_fnleak_a"]
        if not good:
            sys.stderr.write(
                "FAIL: phase-3 over-correction — xref.addr against "
                f"{data_addr:#x} returned 0 matches in pattern_fnleak_a. "
                f"matches={r_real['data']['matches']}\n")
            sys.exit(1)

        print(f"xref cross-function-leak smoke test PASSED "
              f"(data={data_addr:#x}, fn_a_hits={len(good)}, "
              f"fn_b_false_hits={len(bad)})")
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        proc.wait(timeout=5)


if __name__ == "__main__":
    main()
