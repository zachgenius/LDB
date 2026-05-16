#!/usr/bin/env python3
"""Phase-4 cleanup C1 adversarial smoke test
(docs/35-field-report-followups.md §3 phase-4 cleanup C1).

Reproduces the silent-wrong-result regression phase-4 item 1 introduced:
the unconditional adrp_regs.clear() on a cross-function cond branch
killed the fall-through path's tracking, eating a legitimate xref.

Pattern (see tests/fixtures/asm/xref_cond_fallthrough.s):
  src_fn:
    adrp x8, cond_ft_target@PAGE     ; tracked x8
    cbz  x9, other_fn                 ; cross-function cbz
    add  x0, x8, cond_ft_target@PAGEOFF  ; FALL-THROUGH — legitimate xref
    ret

Acceptance:
  - xref.addr against `cond_ft_target` returns >= 1 match attributed
    to `src_fn`. Phase-4-pre-fix returns 0.
"""
import json
import os
import subprocess
import sys


def main():
    if len(sys.argv) != 3:
        sys.stderr.write("usage: test_xref_cond_fallthrough.py <ldbd> <fixture>\n")
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

        r = call("symbol.find", {"target_id": tid, "name": "cond_ft_target"})
        assert r["ok"], r
        data_addr = None
        for m in r["data"]["matches"]:
            if m.get("name") == "cond_ft_target":
                data_addr = m["addr"]
                break
        assert data_addr is not None, f"missing cond_ft_target: {r}"

        # Legitimate fall-through xref MUST surface. Phase-4-pre-fix
        # returned 0 matches here because the unconditional
        # adrp_regs.clear() on the cross-function cbz killed x8's
        # tracking before the fall-through ADD ran.
        r = call("xref.addr", {"target_id": tid, "addr": data_addr})
        assert r["ok"], r

        hits_in_src = [m for m in r["data"]["matches"]
                       if m.get("function") == "src_fn"]
        if not hits_in_src:
            sys.stderr.write(
                "FAIL: phase-4 C1 regression — cross-function cbz cleared "
                "adrp_regs on the fall-through path; the legitimate "
                f"xref against {data_addr:#x} in src_fn vanished. "
                f"All matches: {r['data']['matches']}\n")
            sys.exit(1)

        print(f"xref cond-fallthrough smoke test PASSED "
              f"(data={data_addr:#x}, src_fn_matches={len(hits_in_src)})")
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        proc.wait(timeout=5)


if __name__ == "__main__":
    main()
