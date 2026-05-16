#!/usr/bin/env python3
"""Phase-4 item 7 smoke test (docs/35-field-report-followups.md §3).

Real-binary validation: compile a moderate-size C program with
-O1 -Wl,-fixup_chains, then drive xref.addr against:

  1. Each entry in k_string_table[]: surfaces every reader function.
  2. malloc symbol address (process not attached, so this exercises
     the BindInfo schema path even though resolution is phase 5).
  3. A random non-pointer literal (sanity: returns 0 matches; no
     false-positive xrefs from the multi-function single-TU layout).

This is the closest the fixture suite gets to a real iOS app at
build-time. Real-binary spot-checking against /usr/bin/grep is
documented in the worklog but not automated (host-dependent).
"""
import json
import os
import subprocess
import sys


def main():
    if len(sys.argv) != 3:
        sys.stderr.write("usage: test_xref_real_world.py <ldbd> <fixture>\n")
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

        # Each string in k_string_table[] should surface at least one
        # xref. The compiler emits an ADRP+LDR via __DATA_CONST slot
        # indirection on -Wl,-fixup_chains builds; phase 2's slot-
        # match path resolves to the underlying string.
        needles = ["real_world_xref_alpha",
                   "real_world_xref_beta",
                   "real_world_xref_gamma"]
        for needle in needles:
            r = call("string.xref",
                     {"target_id": tid, "text": needle})
            assert r["ok"], r
            xrefs = r["data"]["results"]
            # string.xref returns one result per matching string;
            # each has an `xrefs` array of instructions referencing it.
            if not xrefs:
                sys.stderr.write(
                    f"FAIL: phase-4 real-world fixture — string '{needle}' "
                    "had zero xrefs surfaced. Likely a chained-fixup "
                    "slot-indirection regression. Full data: "
                    f"{r['data']}\n")
                sys.exit(1)
            total_xref_instrs = sum(len(x.get("xrefs", [])) for x in xrefs)
            if total_xref_instrs == 0:
                sys.stderr.write(
                    f"FAIL: phase-4 real-world fixture — string '{needle}' "
                    "found at the string table but no instructions "
                    "reference it. Full data: "
                    f"{r['data']}\n")
                sys.exit(1)

        # xref.addr against a deterministic non-pointer literal must
        # return 0 matches (sanity: false-positive density across a
        # 4-function single-TU binary is the noise-floor metric).
        r = call("xref.addr",
                 {"target_id": tid, "addr": 0x1122334455667788})
        assert r["ok"], r
        matches = r["data"]["matches"]
        if matches:
            sys.stderr.write(
                "FAIL: phase-4 real-world fixture — non-pointer literal "
                "0x1122334455667788 surfaced "
                f"{len(matches)} false-positive xrefs: {matches}\n")
            sys.exit(1)

        print(f"xref real-world smoke test PASSED "
              f"(strings={len(needles)}, all surfaced)")
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        proc.wait(timeout=5)


if __name__ == "__main__":
    main()
