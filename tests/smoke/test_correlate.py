#!/usr/bin/env python3
"""Smoke test for cross-binary correlation (Tier 3 §10, scoped slice).

End-to-end:
  • describe.endpoints reports correlate.types/symbols/strings.
  • Open structs + sleeper fixtures, take the two target_ids.
  • correlate.types name="point2"
      → structs reports found, sleeper reports missing
      → drift=false (only one in found-set; nothing to compare)
  • correlate.symbols name="main"
      → both fixtures define main; both buckets non-empty
      → addresses likely differ across the two binaries
  • correlate.strings text="LDB_SLEEPER_MARKER_v1"
      → asymmetric: present in sleeper, absent in structs
  • Empty target_ids and unknown target_id → -32602.

LDB_STORE_ROOT is pinned at a tmpdir; never touches ~/.ldb.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile


def usage():
    sys.stderr.write(
        "usage: test_correlate.py <ldbd> <structs_bin> <sleeper_bin>\n")
    sys.exit(2)


def main():
    if len(sys.argv) != 4:
        usage()
    ldbd, structs_bin, sleeper_bin = sys.argv[1:4]
    for p in (ldbd, structs_bin, sleeper_bin):
        if not os.access(p, os.X_OK):
            sys.stderr.write(f"not executable: {p}\n"); sys.exit(1)

    store_root = tempfile.mkdtemp(prefix="ldb_smoke_correlate_")

    try:
        env = dict(os.environ)
        env["LDB_STORE_ROOT"] = store_root
        env.setdefault("LLDB_LOG_LEVEL", "error")
        proc = subprocess.Popen(
            [ldbd, "--stdio", "--log-level", "error"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env, text=True, bufsize=1,
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
                stderr = proc.stderr.read()
                sys.stderr.write(
                    f"daemon closed stdout (stderr was: {stderr})\n")
                sys.exit(1)
            return json.loads(line)

        failures = []
        def expect(cond, msg):
            if not cond: failures.append(msg)

        try:
            # --- describe.endpoints lists all three correlate methods ----
            d = call("describe.endpoints")
            expect(d["ok"], f"describe.endpoints: {d}")
            methods = {e["method"] for e in d["data"]["endpoints"]}
            for m in ("correlate.types", "correlate.symbols",
                      "correlate.strings"):
                expect(m in methods, f"missing endpoint: {m}")

            # --- open both fixtures --------------------------------------
            o1 = call("target.open", {"path": structs_bin})
            expect(o1["ok"], f"target.open structs: {o1}")
            tid_s = o1["data"]["target_id"]

            o2 = call("target.open", {"path": sleeper_bin})
            expect(o2["ok"], f"target.open sleeper: {o2}")
            tid_z = o2["data"]["target_id"]
            expect(tid_s != tid_z, "target_ids must differ")

            # --- correlate.types: point2 is structs-only ----------------
            ct = call("correlate.types",
                      {"target_ids": [tid_s, tid_z], "name": "point2"})
            expect(ct["ok"], f"correlate.types: {ct}")
            results = ct["data"]["results"]
            expect(len(results) == 2, f"expected 2 results: {results}")
            by_id = {r["target_id"]: r for r in results}
            expect(by_id[tid_s]["status"] == "found",
                   f"structs status: {by_id[tid_s]}")
            expect(by_id[tid_z]["status"] == "missing",
                   f"sleeper status: {by_id[tid_z]}")
            # structs's layout has fields, byte_size, alignment.
            layout = by_id[tid_s]["layout"]
            expect(layout is not None, f"structs layout missing: {by_id[tid_s]}")
            expect("byte_size" in layout, f"layout missing byte_size: {layout}")
            expect("fields" in layout, f"layout missing fields: {layout}")
            # Only one in found-set → drift=false, no drift_reason.
            expect(ct["data"]["drift"] is False,
                   f"unexpected drift: {ct['data']}")
            expect("drift_reason" not in ct["data"],
                   f"drift_reason emitted with no drift: {ct['data']}")

            # --- correlate.symbols: both have main --------------------
            cs = call("correlate.symbols",
                      {"target_ids": [tid_s, tid_z], "name": "main"})
            expect(cs["ok"], f"correlate.symbols: {cs}")
            sresults = cs["data"]["results"]
            expect(len(sresults) == 2, f"expected 2 results: {sresults}")
            sby_id = {r["target_id"]: r for r in sresults}
            for tid in (tid_s, tid_z):
                expect(len(sby_id[tid]["matches"]) >= 1,
                       f"main not found in {tid}: {sby_id[tid]}")
            # total counts every match across the result rows.
            sum_matches = sum(len(r["matches"]) for r in sresults)
            expect(cs["data"]["total"] == sum_matches,
                   f"total mismatch: {cs['data']}")

            # --- correlate.strings: asymmetric ------------------------
            cstr = call("correlate.strings",
                        {"target_ids": [tid_s, tid_z],
                         "text": "LDB_SLEEPER_MARKER_v1"})
            expect(cstr["ok"], f"correlate.strings: {cstr}")
            stresults = cstr["data"]["results"]
            expect(len(stresults) == 2, f"expected 2 results: {stresults}")
            stby_id = {r["target_id"]: r for r in stresults}
            # structs has no LDB_SLEEPER_MARKER_v1 string at all.
            expect(stby_id[tid_s]["callsites"] == [],
                   f"structs unexpectedly has callsites: {stby_id[tid_s]}")
            # sleeper has the string defined; whether xrefs are present
            # depends on codegen, but the array must exist.
            expect(isinstance(stby_id[tid_z]["callsites"], list),
                   f"sleeper callsites not array: {stby_id[tid_z]}")

            # --- error paths -----------------------------------------
            bad_id = call("correlate.types",
                          {"target_ids": [tid_s, 9999], "name": "point2"})
            expect(not bad_id["ok"], f"unknown id should fail: {bad_id}")
            expect(bad_id.get("error", {}).get("code") == -32602,
                   f"unknown id code: {bad_id}")
            expect("9999" in bad_id.get("error", {}).get("message", ""),
                   f"unknown id should mention 9999: {bad_id}")

            empty = call("correlate.symbols",
                         {"target_ids": [], "name": "main"})
            expect(not empty["ok"], f"empty list should fail: {empty}")
            expect(empty.get("error", {}).get("code") == -32602,
                   f"empty list code: {empty}")

            # --- duplicate target_ids are silently deduped -----------
            dups = call("correlate.types",
                        {"target_ids": [tid_s, tid_s, tid_s],
                         "name": "point2"})
            expect(dups["ok"], f"dup ids: {dups}")
            expect(len(dups["data"]["results"]) == 1,
                   f"dup ids should produce 1 row: {dups['data']}")
            expect(dups["data"]["drift"] is False,
                   f"dups should not drift: {dups['data']}")

        finally:
            try:
                proc.stdin.close()
            except Exception:
                pass
            proc.wait(timeout=10)

        if failures:
            for f in failures:
                sys.stderr.write(f"FAIL: {f}\n")
            sys.exit(1)
        print("correlate smoke test PASSED")
    finally:
        shutil.rmtree(store_root, ignore_errors=True)


if __name__ == "__main__":
    main()
