#!/usr/bin/env python3
"""Phase-4 adversarial smoke test for the stripped-binary function-
boundary detection (docs/35-field-report-followups.md §3 item 3).

Pattern (see tests/fixtures/asm/xref_stripped_fnleak.s):
  pattern_strip_a:  (local symbol; stripped at link time)
    adrp x19, strip_data@PAGE
    bl   pattern_strip_b   ; AAPCS64: x19 preserved across BL
    ret

  pattern_strip_b:  (local symbol; stripped)
    ldr  x0, [x19, #0x10]   ; phase 3 leaks; phase 4's
                              ; function_starts reset catches the
                              ; boundary (or gate 1 catches it via
                              ; LLDB's synthesised
                              ; ___lldb_unnamed_symbol_<addr> names —
                              ; see implementation note below).
    ret

Acceptance:
  - xref.addr against `strip_data + 0x10` returns ZERO matches in
    any function. The fixture's strip step removes the local
    function labels; phase 3 would leak adrp_regs[x19] from
    pattern_strip_a into pattern_strip_b on a platform where
    function_name_at returns "" for both sides.

Implementation note:
  - On macOS / Apple-silicon, LLDB synthesises a per-address symbol
    name (___lldb_unnamed_symbol_<addr>) for stripped function
    bodies. function_name_at therefore returns DISTINCT names for
    each anonymous function and gate 1 catches the boundary on this
    platform without needing item 3. The smoke test doesn't assert
    on which path fired (function_starts vs gate 1 vs RET-clear) —
    correctness is what matters. Item 3's
    adrp_pair_function_start_reset counter is exercised by the
    chained-fixup smoke test on real binaries where LLDB's
    synthesised names don't always cover every boundary.
"""
import json
import os
import subprocess
import sys


def main():
    if len(sys.argv) != 3:
        sys.stderr.write("usage: test_xref_stripped_fnleak.py <ldbd> <fixture>\n")
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

        r = call("symbol.find", {"target_id": tid, "name": "strip_data"})
        assert r["ok"], r
        data_addr = None
        for m in r["data"]["matches"]:
            if m.get("name") == "strip_data":
                data_addr = m["addr"]
                break
        assert data_addr is not None, f"missing strip_data: {r}"

        false_target = data_addr + 0x10

        # The LDR in pattern_strip_b accesses [x19, #0x10]; with x19
        # holding strip_data's page (would leak from pattern_strip_a
        # if no boundary reset fires), phase 3 would surface one
        # match. Phase 4 layers function_starts on top of gate 1's
        # synthesised-name path; either is sufficient.
        r_false = call("xref.addr",
                       {"target_id": tid, "addr": false_target})
        assert r_false["ok"], r_false
        bad = r_false["data"]["matches"]
        if bad:
            sys.stderr.write(
                "FAIL: phase-4 stripped-binary function-boundary leak — "
                f"xref.addr against {false_target:#x} returned {len(bad)} "
                f"match(es): {bad}\n")
            sys.exit(1)

        prov = r_false["data"].get("provenance", {})
        print(f"xref stripped-binary function-boundary smoke test PASSED "
              f"(data={data_addr:#x}, false_hits=0, "
              f"provenance={prov})")
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        proc.wait(timeout=5)


if __name__ == "__main__":
    main()
