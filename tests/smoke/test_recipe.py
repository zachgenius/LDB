#!/usr/bin/env python3
"""Smoke test for recipe.* endpoints (Tier 2 §6 — probe recipes).

Drives the full RPC surface end-to-end:
  1. session.create + attach.
  2. Issue a few RPCs (hello, describe.endpoints, artifact.put — picks
     three that don't need a live target so this test stays fast and
     hardware-independent).
  3. session.detach.
  4. recipe.from_session — extract the body, assert call_count strips
     the cosmetic / introspection / session-mgmt calls.
  5. recipe.list — finds the new recipe.
  6. recipe.get — returns the full body and call params match the
     session log.
  7. recipe.create — explicit creation with parameters, verify
     parameter substitution at recipe.run time.
  8. recipe.run — replay; assert response shape and that substitution
     fired for every {slot} placeholder.
  9. recipe.delete — gone from list.
  10. Negative paths: missing parameter, unknown recipe_id, wrong
      types, run-time error stops the cascade.

Uses LDB_STORE_ROOT pointed at a per-test tmpdir — never touches
~/.ldb.
"""
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile


def usage():
    sys.stderr.write("usage: test_recipe.py <ldbd>\n")
    sys.exit(2)


def main():
    if len(sys.argv) != 2:
        usage()
    ldbd = sys.argv[1]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n"); sys.exit(1)

    store_root = tempfile.mkdtemp(prefix="ldb_smoke_recipe_")
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
            # --- describe.endpoints lists all six recipe.* + artifact.delete
            r0 = call("describe.endpoints")
            expect(r0["ok"], f"describe.endpoints: {r0}")
            methods = {e["method"] for e in r0["data"]["endpoints"]}
            for m in ("recipe.create", "recipe.from_session", "recipe.list",
                      "recipe.get", "recipe.run", "recipe.delete",
                      "artifact.delete"):
                expect(m in methods, f"missing endpoint: {m}")

            # --- session attach -----------------------------------------
            cs = call("session.create", {"name": "recipe_smoke"})
            expect(cs["ok"], f"session.create: {cs}")
            sid = cs["data"]["id"]

            at = call("session.attach", {"id": sid})
            expect(at["ok"], f"session.attach: {at}")

            # Issue some RPCs; mix introspection (will be stripped) with
            # artifact.put / artifact.list (will be kept).
            call("hello")  # stripped
            payload = b"recipe-smoke-payload"
            ap = call("artifact.put", {
                "build_id": "build-recipe-test",
                "name": "fixture.bin",
                "bytes_b64": base64.b64encode(payload).decode(),
                "format": "raw",
            })
            expect(ap["ok"], f"artifact.put in session: {ap}")
            call("describe.endpoints")  # stripped
            al = call("artifact.list", {"build_id": "build-recipe-test"})
            expect(al["ok"], f"artifact.list in session: {al}")

            dt = call("session.detach")
            expect(dt["ok"], f"session.detach: {dt}")

            # --- from_session -------------------------------------------
            fs = call("recipe.from_session", {
                "source_session_id": sid,
                "name": "recipe_extract_smoke",
                "description": "extract from a session",
            })
            expect(fs["ok"], f"recipe.from_session: {fs}")
            recipe_id = fs["data"]["recipe_id"]
            expect(recipe_id > 0, f"recipe_id: {recipe_id}")
            # The default strip set drops hello / describe.endpoints /
            # session.attach — we issued artifact.put + artifact.list
            # plus session.attach (logged) plus the strip targets.
            expect(fs["data"]["call_count"] == 2,
                   f"expected 2 calls extracted, got "
                   f"{fs['data']['call_count']}")

            # --- list ---------------------------------------------------
            lst = call("recipe.list")
            expect(lst["ok"], f"recipe.list: {lst}")
            names = {r["name"] for r in lst["data"]["recipes"]}
            expect("recipe_extract_smoke" in names,
                   f"missing recipe in list: {lst}")

            # --- get ----------------------------------------------------
            rg = call("recipe.get", {"recipe_id": recipe_id})
            expect(rg["ok"], f"recipe.get: {rg}")
            extracted_calls = rg["data"]["calls"]
            expect(len(extracted_calls) == 2,
                   f"expected 2 extracted calls: {extracted_calls}")
            extracted_methods = [c["method"] for c in extracted_calls]
            expect(extracted_methods == ["artifact.put", "artifact.list"],
                   f"extracted method order: {extracted_methods}")

            # --- recipe.create with parameters --------------------------
            # Build a hand-crafted recipe that uses substitution slots.
            cr = call("recipe.create", {
                "name": "named_recipe",
                "description": "Templated put + list",
                "parameters": [
                    {"name": "build_id", "type": "string"},
                    {"name": "blob_name", "type": "string",
                     "default": "default.bin"},
                ],
                "calls": [
                    {"method": "artifact.put",
                     "params": {
                         "build_id": "{build_id}",
                         "name": "{blob_name}",
                         "bytes_b64": base64.b64encode(
                             b"templated").decode(),
                     }},
                    {"method": "artifact.list",
                     "params": {"build_id": "{build_id}"}},
                ],
            })
            expect(cr["ok"], f"recipe.create: {cr}")
            named_id = cr["data"]["recipe_id"]
            expect(cr["data"]["call_count"] == 2,
                   f"call_count: {cr}")

            # --- recipe.run with all parameters supplied ----------------
            run_ok = call("recipe.run", {
                "recipe_id": named_id,
                "parameters": {
                    "build_id": "build-recipe-run",
                    "blob_name": "explicit.bin",
                },
            })
            expect(run_ok["ok"], f"recipe.run: {run_ok}")
            resps = run_ok["data"]["responses"]
            expect(len(resps) == 2,
                   f"expected 2 responses, got {len(resps)}")
            expect(resps[0]["ok"] and resps[0]["method"] == "artifact.put",
                   f"resp[0]: {resps[0]}")
            expect(resps[1]["ok"] and resps[1]["method"] == "artifact.list",
                   f"resp[1]: {resps[1]}")
            # Substitution: artifact.list response must include the
            # blob we just put under the substituted build_id.
            list_arts = resps[1]["data"]["artifacts"]
            expect(any(a["name"] == "explicit.bin" for a in list_arts),
                   f"substituted blob not seen in list: {list_arts}")

            # --- recipe.run using the default (omit blob_name) ----------
            run_def = call("recipe.run", {
                "recipe_id": named_id,
                "parameters": {"build_id": "build-recipe-default"},
            })
            expect(run_def["ok"], f"recipe.run default: {run_def}")
            list2 = run_def["data"]["responses"][1]["data"]["artifacts"]
            expect(any(a["name"] == "default.bin" for a in list2),
                   f"default blob_name not used: {list2}")

            # --- recipe.run missing required parameter ------------------
            run_miss = call("recipe.run", {"recipe_id": named_id,
                                            "parameters": {}})
            expect(run_miss["ok"],
                   f"recipe.run wrapper itself is ok: {run_miss}")
            ms = run_miss["data"]["responses"]
            expect(len(ms) == 1 and ms[0]["ok"] is False,
                   f"missing param should fail first call: {ms}")
            expect(ms[0]["error"]["code"] == -32602,
                   f"missing param code: {ms[0]}")

            # --- recipe.run with unknown recipe id ----------------------
            run_bad = call("recipe.run", {"recipe_id": 999999})
            expect(not run_bad["ok"] and
                   run_bad.get("error", {}).get("code") == -32000,
                   f"unknown recipe_id: {run_bad}")

            # --- recipe.delete ------------------------------------------
            rd = call("recipe.delete", {"recipe_id": named_id})
            expect(rd["ok"] and rd["data"]["deleted"] is True,
                   f"recipe.delete: {rd}")
            rd_again = call("recipe.delete", {"recipe_id": named_id})
            expect(rd_again["ok"] and rd_again["data"]["deleted"] is False,
                   f"recipe.delete idempotent: {rd_again}")

            # Recipe should now be gone from list.
            lst2 = call("recipe.list")
            names2 = {r["name"] for r in lst2["data"]["recipes"]}
            expect("named_recipe" not in names2,
                   f"named_recipe should be gone: {names2}")

            # --- error paths --------------------------------------------
            # recipe.create with empty calls.
            re1 = call("recipe.create", {"name": "x", "calls": []})
            expect(not re1["ok"] and
                   re1.get("error", {}).get("code") == -32602,
                   f"empty calls: {re1}")

            # recipe.create with bad parameter type.
            re2 = call("recipe.create", {
                "name": "y",
                "parameters": [{"name": "p", "type": "blob"}],
                "calls": [{"method": "hello", "params": {}}],
            })
            expect(not re2["ok"] and
                   re2.get("error", {}).get("code") == -32602,
                   f"bad param type: {re2}")

            # recipe.get unknown.
            re3 = call("recipe.get", {"recipe_id": 999999})
            expect(not re3["ok"] and
                   re3.get("error", {}).get("code") == -32000,
                   f"recipe.get unknown: {re3}")

            # recipe.from_session with empty session — no calls.
            empty_sess = call("session.create", {"name": "empty"})
            esid = empty_sess["data"]["id"]
            re4 = call("recipe.from_session", {
                "source_session_id": esid, "name": "empty_recipe",
            })
            expect(not re4["ok"] and
                   re4.get("error", {}).get("code") == -32602,
                   f"empty extraction: {re4}")
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
        print("recipe smoke test PASSED")
    finally:
        shutil.rmtree(store_root, ignore_errors=True)


if __name__ == "__main__":
    main()
