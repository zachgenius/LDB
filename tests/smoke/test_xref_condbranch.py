#!/usr/bin/env python3
"""Phase-4 adversarial smoke test for the ADRP-pair resolver's
conditional-branch boundary handling (docs/35-field-report-followups.md
§3 item 1).

Pattern (see tests/fixtures/asm/xref_condbranch.s):
  pattern_cond_a:
    adrp x8, cond_data_a@PAGE
    cbz  x9, pattern_cond_other     ; cbz to a DIFFERENT function
    ret

  pattern_cond_other:
    ldr  x0, [x8, #0x10]            ; x8 undefined; phase 3 leaks.

Acceptance:
  - xref.addr against `cond_data_a + 0x10` returns ZERO matches in
    pattern_cond_other. Phase-4 cleanup C1+C2 reframed the reset:
    instead of clobbering adrp_regs on the source side (which broke
    the fall-through path), the cross-function branch target is
    recorded as a function_start hint. Gate 3 then fires when the
    scanner reaches that target on a later iteration. Either way,
    pattern_cond_other must NOT inherit pattern_cond_a's x8.
  - The response carries provenance.adrp_pair_cond_branch_recorded > 0
    proving phase 4's new code path fired. The counter was renamed
    from `*_reset` to `*_recorded` in the cleanup pass — the source
    side no longer "resets", it records the target.
"""
import json
import os
import subprocess
import sys


def main():
    if len(sys.argv) != 3:
        sys.stderr.write("usage: test_xref_condbranch.py <ldbd> <fixture>\n")
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

        r = call("symbol.find", {"target_id": tid, "name": "cond_data_a"})
        assert r["ok"], r
        data_addr = None
        for m in r["data"]["matches"]:
            if m.get("name") == "cond_data_a":
                data_addr = m["addr"]
                break
        assert data_addr is not None, f"missing cond_data_a: {r}"

        false_target = data_addr + 0x10

        # The false-positive target must produce ZERO matches in
        # pattern_cond_other.
        r_false = call("xref.addr",
                       {"target_id": tid, "addr": false_target})
        assert r_false["ok"], r_false
        bad = [m for m in r_false["data"]["matches"]
               if m.get("function") == "pattern_cond_other"]
        if bad:
            sys.stderr.write(
                "FAIL: phase-4 conditional-branch boundary leak — "
                f"xref.addr against {false_target:#x} returned {len(bad)} "
                f"match(es) in pattern_cond_other: {bad}\n")
            sys.exit(1)

        # The provenance counter proves phase 4's new code path fired.
        # Post-cleanup the counter is `adrp_pair_cond_branch_recorded`
        # — the source-side "reset" was the C1 silent-wrong-result bug.
        prov = r_false["data"].get("provenance", {})
        cond_recorded = prov.get("adrp_pair_cond_branch_recorded", 0)
        if cond_recorded < 1:
            sys.stderr.write(
                "FAIL: phase-4 conditional-branch path didn't fire — "
                "expected provenance.adrp_pair_cond_branch_recorded >= 1 "
                f"after cross-function cbz; got {cond_recorded}. "
                f"Full provenance: {prov}\n")
            sys.exit(1)

        print(f"xref conditional-branch boundary smoke test PASSED "
              f"(data={data_addr:#x}, fn_other_false_hits={len(bad)}, "
              f"cond_recorded_count={cond_recorded})")
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        proc.wait(timeout=5)


if __name__ == "__main__":
    main()
