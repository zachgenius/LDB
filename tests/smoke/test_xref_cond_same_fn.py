#!/usr/bin/env python3
"""Phase-4 cleanup C2 adversarial smoke test
(docs/35-field-report-followups.md §3 phase-4 cleanup C2).

Reproduces the silent-wrong-result regression from phase-4 item 1's
unconditional function_starts insert on cbz targets. A SAME-FUNCTION
cbz to a local label poisoned function_starts, then gate 3 reset
adrp_regs at the label, killing the xref on the post-label consumer.

Pattern (see tests/fixtures/asm/xref_cond_same_fn.s):
  same_fn_test:
    adrp x8, same_fn_data@PAGE
    cbz  x0, Lhere                 ; same-function cbz
    nop
  Lhere:
    add  x10, x8, #0x20            ; legitimate xref
    ret

Acceptance:
  - xref.addr against `same_fn_data + 0x20` returns >= 1 match
    attributed to `same_fn_test`. Phase-4-pre-fix returns 0 because
    Lhere lands in function_starts and gate 3 clears adrp_regs at it.
"""
import json
import os
import subprocess
import sys


def main():
    if len(sys.argv) != 3:
        sys.stderr.write("usage: test_xref_cond_same_fn.py <ldbd> <fixture>\n")
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

        r = call("symbol.find", {"target_id": tid, "name": "same_fn_data"})
        assert r["ok"], r
        data_addr = None
        for m in r["data"]["matches"]:
            if m.get("name") == "same_fn_data":
                data_addr = m["addr"]
                break
        assert data_addr is not None, f"missing same_fn_data: {r}"

        target_addr = data_addr + 0x20

        r = call("xref.addr", {"target_id": tid, "addr": target_addr})
        assert r["ok"], r

        hits = [m for m in r["data"]["matches"]
                if m.get("function") == "same_fn_test"]
        if not hits:
            sys.stderr.write(
                "FAIL: phase-4 C2 regression — same-function cbz target "
                "landed in function_starts; gate 3 reset adrp_regs at the "
                f"local label; the legitimate xref against {target_addr:#x} "
                "in same_fn_test vanished. "
                f"All matches: {r['data']['matches']}\n")
            sys.exit(1)

        print(f"xref cond-same-fn smoke test PASSED "
              f"(target={target_addr:#x}, same_fn_test_matches={len(hits)})")
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        proc.wait(timeout=5)


if __name__ == "__main__":
    main()
