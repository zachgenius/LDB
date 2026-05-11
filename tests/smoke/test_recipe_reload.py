#!/usr/bin/env python3
"""Smoke test for recipe.reload + LDB_RECIPE_DIR startup scan
(post-V1 plan #3).

Covers:
  * LDB_RECIPE_DIR populates the store at daemon startup — recipe.list
    returns the loaded recipes with source_path set.
  * recipe.reload({recipe_id}) re-reads the file, replaces the entry
    (new artifact id), and surfaces the previous_recipe_id alongside
    updated lint warnings.
  * recipe.reload on a non-file-backed recipe (created in-band via
    recipe.create) returns -32003 forbidden.
"""
import json
import os
import subprocess
import sys
import tempfile


def usage():
    sys.stderr.write("usage: test_recipe_reload.py <ldbd>\n")
    sys.exit(2)


def main():
    if len(sys.argv) != 2:
        usage()
    ldbd = sys.argv[1]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n")
        sys.exit(1)

    store_root = tempfile.mkdtemp(prefix="ldb_smoke_reload_store_")
    recipe_dir = tempfile.mkdtemp(prefix="ldb_smoke_reload_recipes_")

    # Write a recipe file with one call.
    recipe_path = os.path.join(recipe_dir, "demo.json")
    with open(recipe_path, "w", encoding="utf-8") as f:
        json.dump({
            "name": "demo",
            "description": "smoke recipe",
            "parameters": [{"name": "path", "type": "string"}],
            "calls": [
                {"method": "target.open", "params": {"path": "{path}"}},
            ],
        }, f)

    env = dict(os.environ)
    env["LDB_STORE_ROOT"] = store_root
    env["LDB_RECIPE_DIR"] = recipe_dir
    env.setdefault("LLDB_LOG_LEVEL", "error")

    proc = subprocess.Popen(
        [ldbd, "--stdio", "--log-level", "error"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
        bufsize=1,
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
            sys.stderr.write(f"daemon closed stdout (stderr: {stderr})\n")
            sys.exit(1)
        return json.loads(line)

    failures = []

    def expect(cond, msg):
        if not cond:
            failures.append(msg)

    try:
        # 1. Startup scan should have loaded the file-backed recipe.
        listed = call("recipe.list", {})
        expect(listed["ok"], f"recipe.list (post-scan): {listed}")
        recipes = listed["data"]["recipes"]
        expect(len(recipes) == 1,
               f"expected 1 file-backed recipe, got {len(recipes)}: {recipes}")
        original_id = recipes[0]["recipe_id"]
        expect("source_path" in recipes[0],
               f"file-backed recipe should have source_path: {recipes[0]}")

        # 2. Verify source_path is present via recipe.get.
        got = call("recipe.get", {"recipe_id": original_id})
        expect(got["ok"], f"recipe.get: {got}")

        # 3. Modify the file on disk — add a second call.
        with open(recipe_path, "w", encoding="utf-8") as f:
            json.dump({
                "name": "demo",
                "description": "smoke recipe v2",
                "parameters": [{"name": "path", "type": "string"}],
                "calls": [
                    {"method": "target.open", "params": {"path": "{path}"}},
                    {"method": "module.list", "params": {"target_id": 1}},
                ],
            }, f)

        # 4. recipe.reload picks up the change.
        reloaded = call("recipe.reload", {"recipe_id": original_id})
        expect(reloaded["ok"], f"recipe.reload: {reloaded}")
        data = reloaded["data"]
        expect(data["call_count"] == 2,
               f"reload call_count: {data}")
        expect(data["name"] == "demo", f"reload name: {data}")
        expect(data.get("previous_recipe_id") == original_id,
               f"previous_recipe_id missing or wrong: {data}")
        new_id = data["recipe_id"]
        expect(new_id != original_id,
               f"recipe_id should change on replace: {data}")
        expect("warnings" in data, f"warnings missing: {data}")

        # 5. Old id no longer resolves.
        stale = call("recipe.get", {"recipe_id": original_id})
        expect(not stale["ok"],
               f"old recipe_id should be gone after reload: {stale}")

        # 6. Negative: reload on a non-file-backed recipe → -32003.
        created = call("recipe.create", {
            "name": "in_band",
            "calls": [{"method": "hello", "params": {}}],
        })
        expect(created["ok"], f"recipe.create: {created}")
        in_band_id = created["data"]["recipe_id"]
        bad = call("recipe.reload", {"recipe_id": in_band_id})
        expect(not bad["ok"], f"in-band reload should fail: {bad}")
        expect(bad.get("error", {}).get("code") == -32003,
               f"in-band reload expected -32003, got {bad}")

        # 7. Negative: missing recipe_id → -32602.
        miss = call("recipe.reload", {})
        expect(not miss["ok"] and
               miss.get("error", {}).get("code") == -32602,
               f"missing recipe_id expected -32602, got {miss}")

        # 8. Schema: recipe.reload registered in describe.endpoints.
        desc = call("describe.endpoints", {})
        expect(desc["ok"], f"describe.endpoints: {desc}")
        methods = {e["method"] for e in desc["data"]["endpoints"]}
        expect("recipe.reload" in methods,
               f"recipe.reload not in describe.endpoints: "
               f"{[m for m in methods if 'recipe' in m]}")
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        proc.wait(timeout=10)
        import shutil
        shutil.rmtree(store_root, ignore_errors=True)
        shutil.rmtree(recipe_dir, ignore_errors=True)

    if failures:
        for f in failures:
            sys.stderr.write(f"FAIL: {f}\n")
        sys.exit(1)
    print("recipe_reload smoke test PASSED")


if __name__ == "__main__":
    main()
