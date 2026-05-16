#!/usr/bin/env python3
"""Phase-4 smoke test for PC-relative literal-load provenance bumping
(docs/35-field-report-followups.md §3 item 4).

Pattern (see tests/fixtures/asm/xref_pcrel_literal.s):
  pattern_pcrel:
    ldr x0, pcrel_const     ; PC-relative literal load
    ret
  pcrel_const:
    .quad pcrel_data        ; literal pool slot

Acceptance:
  - xref.addr against `pcrel_data` returns ZERO matches (no static
    resolution today). This is the existing behaviour.
  - provenance.adrp_pair_unresolvable_load > 0 after the call —
    proves the new code path saw the literal-load shape and bumped
    the counter, surfacing to callers that the heuristic gave up
    on this load.
"""
import json
import os
import subprocess
import sys


def main():
    if len(sys.argv) != 3:
        sys.stderr.write("usage: test_xref_pcrel_literal.py <ldbd> <fixture>\n")
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

        r = call("symbol.find", {"target_id": tid, "name": "pcrel_data"})
        assert r["ok"], r
        data_addr = None
        for m in r["data"]["matches"]:
            if m.get("name") == "pcrel_data":
                data_addr = m["addr"]
                break
        assert data_addr is not None, f"missing pcrel_data: {r}"

        r = call("xref.addr", {"target_id": tid, "addr": data_addr})
        assert r["ok"], r

        prov = r["data"].get("provenance", {})
        unres = prov.get("adrp_pair_unresolvable_load", 0)
        if unres < 1:
            sys.stderr.write(
                "FAIL: phase-4 PC-relative literal load not surfaced — "
                "expected provenance.adrp_pair_unresolvable_load >= 1 "
                f"after a `ldr xN, foo_const` shape; got {unres}. "
                f"Full provenance: {prov}\n")
            sys.exit(1)

        print(f"xref pcrel-literal-load smoke test PASSED "
              f"(data={data_addr:#x}, unresolvable_load_count={unres})")
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        proc.wait(timeout=5)


if __name__ == "__main__":
    main()
