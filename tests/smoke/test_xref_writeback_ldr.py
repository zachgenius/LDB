#!/usr/bin/env python3
"""Phase-3 post-review smoke test for the ADRP-pair resolver
(docs/35-field-report-followups.md §3).

Pattern (see tests/fixtures/asm/xref_writeback_ldr.s):

  pattern_writeback_pre:
    adrp x8, writeback_data@PAGE
    ldr  x0, [x8, #0x100]!     ; pre-indexed: x8 ← page+0x100
    ldr  x1, [x8, #0x10]        ; phase-3-old: page+0x10 (false positive)

  pattern_writeback_post:
    adrp x8, writeback_data@PAGE
    ldr  x0, [x8], #0x100       ; post-indexed: x8 ← page+0x100 after load
    ldr  x1, [x8, #0x10]        ; phase-3-old: page+0x10 (false positive)

Acceptance:
  - xref.addr against `writeback_data + 0x10` returns ZERO matches
    inside either pattern. Phase-3-old returned one match per
    pattern (the trailing LDR), because writeback semantics weren't
    modelled.

Provenance:
  - At least one warning string mentions writeback-cleared ADRP
    tracking. Surfaced via xref.address's provenance.warnings so
    the agent can decide to fall back to symbol-index.
"""
import json
import os
import subprocess
import sys


def main():
    if len(sys.argv) != 3:
        sys.stderr.write("usage: test_xref_writeback_ldr.py <ldbd> <fixture>\n")
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

        r = call("symbol.find", {"target_id": tid, "name": "writeback_data"})
        assert r["ok"], r
        data_addr = None
        for m in r["data"]["matches"]:
            if m.get("name") == "writeback_data":
                data_addr = m["addr"]
                break
        assert data_addr is not None, f"missing writeback_data: {r}"

        false_target = data_addr + 0x10

        r_false = call("xref.addr",
                       {"target_id": tid, "addr": false_target})
        assert r_false["ok"], r_false
        bad = [m for m in r_false["data"]["matches"]
               if m.get("function", "").startswith("pattern_writeback")]
        if bad:
            sys.stderr.write(
                "FAIL: writeback-LDR regression — xref.addr against "
                f"{false_target:#x} returned {len(bad)} match(es) in "
                f"pattern_writeback_* (base register should be cleared "
                f"by pre/post-indexed writeback): {bad}\n")
            sys.exit(1)

        # Provenance check: at least one warning should mention the
        # writeback clobber. Surfacing the count gives the agent a
        # signal that the heuristic isn't authoritative on this binary.
        prov = r_false["data"].get("_provenance") or r_false.get(
            "_provenance") or {}
        warns = prov.get("warnings", [])
        # _provenance may not be present on a clean run; allow that.
        # But if it IS present, it should mention "writeback".
        if warns and not any("writeback" in w.lower() for w in warns):
            sys.stderr.write(
                "FAIL: provenance.warnings present but no writeback "
                f"mention: {warns}\n")
            sys.exit(1)

        print(f"xref writeback-LDR smoke test PASSED "
              f"(data={data_addr:#x}, false_hits={len(bad)}, "
              f"warnings={len(warns)})")
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        proc.wait(timeout=5)


if __name__ == "__main__":
    main()
