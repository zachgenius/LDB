#!/usr/bin/env python3
"""Phase-3 adversarial smoke test for the ADRP-pair resolver
(docs/35-field-report-followups.md §3).

Pattern (see tests/fixtures/asm/xref_callclobber.s):
  pattern_callclobber:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    adrp x0, callclobber_data@PAGE   ; x0 = page (caller-saved)
    bl   _callclobber_helper           ; AAPCS64: x0..x18 + x30 clobbered
    ldr  x1, [x0, #0x10]               ; x0 here is helper's retval
    ...

Acceptance:
  - xref.addr against `callclobber_data + 0x10` returns ZERO matches
    inside pattern_callclobber. Phase 2 returns one (the LDR), because
    its register-state map didn't clear x0 on the BL.
"""
import json
import os
import subprocess
import sys


def main():
    if len(sys.argv) != 3:
        sys.stderr.write("usage: test_xref_callclobber.py <ldbd> <fixture>\n")
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

        r = call("symbol.find", {"target_id": tid, "name": "callclobber_data"})
        assert r["ok"], r
        data_addr = None
        for m in r["data"]["matches"]:
            if m.get("name") == "callclobber_data":
                data_addr = m["addr"]
                break
        assert data_addr is not None, f"missing callclobber_data: {r}"

        false_target = data_addr + 0x10

        r_false = call("xref.addr",
                       {"target_id": tid, "addr": false_target})
        assert r_false["ok"], r_false
        bad = [m for m in r_false["data"]["matches"]
               if m.get("function") == "pattern_callclobber"]
        if bad:
            sys.stderr.write(
                "FAIL: phase-3 BL-clobber regression — xref.addr against "
                f"{false_target:#x} returned {len(bad)} match(es) in "
                f"pattern_callclobber (x0 should be dead after BL): {bad}\n")
            sys.exit(1)

        print(f"xref BL-clobber smoke test PASSED "
              f"(data={data_addr:#x}, false_hits={len(bad)})")
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        proc.wait(timeout=5)


if __name__ == "__main__":
    main()
