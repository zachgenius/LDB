#!/usr/bin/env python3
"""Smoke test for static.globals_of_type (Tier 3 §12, semantic queries v1).

End-to-end:
  - describe.endpoints reports static.globals_of_type with the expected
    schema (params requires target_id + type_name; cost_hint=medium;
    requires_target=true).
  - target.open the structs fixture, then exercise:
      * Exact match: type_name="point2" -> 1 result (g_origin),
        type_match_strict=true.
      * Multi exact match: type_name="const char *const" -> 2 results
        (k_schema_name, k_protocol_name), strict=true.
      * Substring fallback: type_name="dxp_login" -> 1 result
        (g_login_template), strict=false.
      * Unknown type: type_name="unknown_type_42" -> empty, strict=false.
      * Empty type_name -> -32602 kInvalidParams.
      * Missing type_name -> -32602 kInvalidParams.
  - view.limit slices the globals array; total stays the full count.
"""
import json
import os
import subprocess
import sys


def usage():
    sys.stderr.write(
        "usage: test_static_globals.py <ldbd> <structs-fixture>\n")
    sys.exit(2)


def main():
    if len(sys.argv) != 3:
        usage()
    ldbd, fixture = sys.argv[1], sys.argv[2]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n"); sys.exit(1)
    if not os.access(fixture, os.R_OK):
        sys.stderr.write(f"fixture not readable: {fixture}\n"); sys.exit(1)

    env = dict(os.environ)
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
        proc.stdin.write(json.dumps(req) + "\n"); proc.stdin.flush()
        line = proc.stdout.readline()
        if not line:
            stderr = proc.stderr.read()
            sys.stderr.write(f"daemon closed stdout (stderr was: {stderr})\n")
            sys.exit(1)
        return json.loads(line)

    failures = []
    def expect(cond, msg):
        if not cond:
            failures.append(msg)

    try:
        # --- describe.endpoints reports static.globals_of_type --------
        d = call("describe.endpoints")
        expect(d.get("ok"), f"describe.endpoints: {d}")
        ep = None
        for e in d["data"]["endpoints"]:
            if e.get("method") == "static.globals_of_type":
                ep = e; break
        expect(ep is not None, "static.globals_of_type not in catalog")
        if ep:
            req_keys = ep["params_schema"].get("required", [])
            expect("target_id" in req_keys, "schema requires target_id")
            expect("type_name" in req_keys, "schema requires type_name")
            expect(ep.get("requires_target") is True,
                   "requires_target should be true")
            expect(ep.get("cost_hint") == "medium",
                   f"cost_hint expected medium, got {ep.get('cost_hint')}")
            ret = ep["returns_schema"]
            ret_req = ret.get("required", [])
            expect("globals" in ret_req, "returns require globals")
            expect("type_match_strict" in ret_req,
                   "returns require type_match_strict")

        # --- open the structs fixture --------------------------------
        o = call("target.open", {"path": fixture})
        expect(o.get("ok"), f"target.open: {o}")
        tid = o["data"]["target_id"]

        # --- Exact match: type_name="point2" -> 1 result --------------
        r = call("static.globals_of_type",
                 {"target_id": tid, "type_name": "point2"})
        expect(r.get("ok"), f"point2: {r}")
        if r.get("ok"):
            data = r["data"]
            expect(data["type_match_strict"] is True,
                   f"point2 strict: {data}")
            expect(data["total"] == 1, f"point2 total: {data}")
            expect(len(data["globals"]) == 1, f"point2 len: {data}")
            g = data["globals"][0]
            expect(g["name"] == "g_origin", f"point2 name: {g}")
            expect(g["type"] == "point2", f"point2 type: {g}")
            expect(g["sz"] == 8, f"point2 sz: {g}")
            expect(g["addr"] != 0, f"point2 addr: {g}")
            # No process attached -> no load_addr
            expect("load_addr" not in g, f"point2 load_addr: {g}")
            expect(g.get("file") == "structs.c", f"point2 file: {g}")
            expect(g.get("line") == 46, f"point2 line: {g}")

        # --- Multiple exact matches: const char *const ----------------
        r = call("static.globals_of_type",
                 {"target_id": tid, "type_name": "const char *const"})
        expect(r.get("ok"), f"const char *const: {r}")
        if r.get("ok"):
            data = r["data"]
            expect(data["type_match_strict"] is True,
                   f"cccc strict: {data}")
            expect(data["total"] == 2, f"cccc total: {data}")
            names = sorted(g["name"] for g in data["globals"])
            expect(names == ["k_protocol_name", "k_schema_name"],
                   f"cccc names: {names}")

        # --- Substring fallback ---------------------------------------
        r = call("static.globals_of_type",
                 {"target_id": tid, "type_name": "dxp_login"})
        expect(r.get("ok"), f"dxp_login: {r}")
        if r.get("ok"):
            data = r["data"]
            expect(data["type_match_strict"] is False,
                   f"dxp_login strict: {data}")
            expect(data["total"] == 1, f"dxp_login total: {data}")
            expect(data["globals"][0]["name"] == "g_login_template",
                   f"dxp_login name: {data}")
            expect(data["globals"][0]["type"] == "dxp_login_frame",
                   f"dxp_login type: {data}")

        # --- Unknown type --------------------------------------------
        r = call("static.globals_of_type",
                 {"target_id": tid, "type_name": "unknown_type_42"})
        expect(r.get("ok"), f"unknown: {r}")
        if r.get("ok"):
            data = r["data"]
            expect(data["type_match_strict"] is False,
                   f"unknown strict: {data}")
            expect(data["total"] == 0, f"unknown total: {data}")
            expect(data["globals"] == [], f"unknown globals: {data}")

        # --- view.limit clips ----------------------------------------
        r = call("static.globals_of_type",
                 {"target_id": tid, "type_name": "const char *const",
                  "view": {"limit": 1}})
        expect(r.get("ok"), f"view.limit: {r}")
        if r.get("ok"):
            data = r["data"]
            expect(data["total"] == 2, f"view.limit total: {data}")
            expect(len(data["globals"]) == 1,
                   f"view.limit len: {data}")

        # --- Negative: empty type_name -------------------------------
        r = call("static.globals_of_type",
                 {"target_id": tid, "type_name": ""})
        expect(not r.get("ok"), f"empty should fail: {r}")
        expect(r.get("error", {}).get("code") == -32602,
               f"empty error code: {r}")

        # --- Negative: missing type_name -----------------------------
        r = call("static.globals_of_type", {"target_id": tid})
        expect(not r.get("ok"), f"missing should fail: {r}")
        expect(r.get("error", {}).get("code") == -32602,
               f"missing error code: {r}")

    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        proc.wait(timeout=5)

    if failures:
        sys.stderr.write("FAIL:\n")
        for f in failures:
            sys.stderr.write(f"  - {f}\n")
        sys.exit(1)
    print("PASS")


if __name__ == "__main__":
    main()
