#!/usr/bin/env python3
"""Smoke test for artifact.relate / artifact.relations / artifact.unrelate
(Tier 3 §7).

End-to-end via the daemon's stdio JSON-RPC channel: stand up two
artifacts, relate them, list, unrelate, list-now-empty. Plus the negative
paths the dispatcher unit test can't cover (live wire shape).
"""
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile


def usage():
    sys.stderr.write("usage: test_artifact_relations.py <ldbd>\n")
    sys.exit(2)


def main():
    if len(sys.argv) != 2:
        usage()
    ldbd = sys.argv[1]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n"); sys.exit(1)

    store_root = tempfile.mkdtemp(prefix="ldb_smoke_relations_")

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
            # --- describe.endpoints lists the new methods --------------
            r0 = call("describe.endpoints")
            expect(r0["ok"], f"describe.endpoints: {r0}")
            methods = {e["method"] for e in r0["data"]["endpoints"]}
            for m in ("artifact.relate", "artifact.relations",
                      "artifact.unrelate"):
                expect(m in methods, f"missing endpoint: {m}")

            # --- seed two artifacts ------------------------------------
            r1 = call("artifact.put", {
                "build_id": "build-cafe",
                "name": "schema.xml",
                "bytes_b64": base64.b64encode(b"<schema/>").decode(),
                "format": "xml",
            })
            expect(r1["ok"], f"put #1: {r1}")
            id1 = r1["data"]["id"]

            r2 = call("artifact.put", {
                "build_id": "build-cafe",
                "name": "frame.bin",
                "bytes_b64": base64.b64encode(b"\x01\x02\x03").decode(),
            })
            expect(r2["ok"], f"put #2: {r2}")
            id2 = r2["data"]["id"]

            # --- relate ------------------------------------------------
            rr = call("artifact.relate", {
                "from_id":   id1,
                "to_id":     id2,
                "predicate": "parsed_by",
                "meta":      {"function": "xml_parse", "line": 42},
            })
            expect(rr["ok"], f"relate: {rr}")
            rel_id = rr["data"]["relation_id"]
            expect(rel_id > 0, f"bad relation_id: {rel_id}")
            expect(rr["data"]["from_id"] == id1, f"from_id: {rr}")
            expect(rr["data"]["to_id"] == id2, f"to_id: {rr}")
            expect(rr["data"]["predicate"] == "parsed_by",
                   f"predicate: {rr}")
            expect(rr["data"]["created_at"] > 0, f"created_at: {rr}")

            # --- list (no filter) --------------------------------------
            rl = call("artifact.relations", {})
            expect(rl["ok"], f"list: {rl}")
            expect(rl["data"]["total"] == 1, f"total: {rl}")
            expect(len(rl["data"]["relations"]) == 1,
                   f"relations len: {rl}")
            row = rl["data"]["relations"][0]
            expect(row["id"] == rel_id, f"row id: {row}")
            expect(row["meta"]["function"] == "xml_parse",
                   f"meta: {row}")

            # --- list (predicate filter, hit/miss) ---------------------
            rl_hit = call("artifact.relations", {"predicate": "parsed_by"})
            expect(rl_hit["ok"] and rl_hit["data"]["total"] == 1,
                   f"predicate hit: {rl_hit}")

            rl_miss = call("artifact.relations",
                           {"predicate": "no_such_predicate"})
            expect(rl_miss["ok"] and rl_miss["data"]["total"] == 0,
                   f"predicate miss: {rl_miss}")

            # --- list (direction filter) -------------------------------
            rl_out = call("artifact.relations",
                          {"artifact_id": id1, "direction": "out"})
            expect(rl_out["ok"] and rl_out["data"]["total"] == 1,
                   f"out: {rl_out}")
            rl_in = call("artifact.relations",
                         {"artifact_id": id1, "direction": "in"})
            expect(rl_in["ok"] and rl_in["data"]["total"] == 0,
                   f"in: {rl_in}")
            rl_both = call("artifact.relations",
                           {"artifact_id": id1, "direction": "both"})
            expect(rl_both["ok"] and rl_both["data"]["total"] == 1,
                   f"both: {rl_both}")

            # --- view::apply_to_array on the relations array -----------
            # Add a couple more so paging is meaningful.
            for p in ("extracted_from", "called_by"):
                call("artifact.relate", {
                    "from_id": id1, "to_id": id2, "predicate": p,
                })
            paged = call("artifact.relations",
                         {"view": {"limit": 1, "offset": 1}})
            expect(paged["ok"], f"paged: {paged}")
            expect(paged["data"]["total"] == 3,
                   f"paged total: {paged}")
            expect(len(paged["data"]["relations"]) == 1,
                   f"paged len: {paged}")

            # --- unrelate ----------------------------------------------
            ru = call("artifact.unrelate", {"relation_id": rel_id})
            expect(ru["ok"] and ru["data"]["deleted"] is True,
                   f"unrelate: {ru}")
            ru_again = call("artifact.unrelate", {"relation_id": rel_id})
            expect(ru_again["ok"] and ru_again["data"]["deleted"] is False,
                   f"unrelate idempotent: {ru_again}")

            # --- ON DELETE CASCADE on artifact.delete ------------------
            # Drop id1; should also drop the remaining 2 relations.
            rd = call("artifact.delete", {"id": id1})
            expect(rd["ok"], f"delete artifact: {rd}")
            rl_after = call("artifact.relations", {})
            expect(rl_after["ok"] and rl_after["data"]["total"] == 0,
                   f"cascade should clear relations: {rl_after}")

            # --- error paths ------------------------------------------
            # Missing predicate.
            re1 = call("artifact.relate",
                       {"from_id": id1, "to_id": id2})
            expect(not re1["ok"] and
                   re1.get("error", {}).get("code") == -32602,
                   f"missing predicate: {re1}")

            # Missing relation_id on unrelate.
            re2 = call("artifact.unrelate", {})
            expect(not re2["ok"] and
                   re2.get("error", {}).get("code") == -32602,
                   f"missing relation_id: {re2}")
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
        print("artifact relations smoke test PASSED")
    finally:
        shutil.rmtree(store_root, ignore_errors=True)


if __name__ == "__main__":
    main()
