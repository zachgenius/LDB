#!/usr/bin/env python3
"""Smoke test for python-v1 recipes (post-V1 #9 phase-2).

Drives the full python-v1 recipe surface end-to-end:

  1. recipe.create with format="python-v1" + body=<source> — stores the
     recipe, returns a positive recipe_id.
  2. recipe.lint against the python recipe — valid Python returns
     `warnings: []`; intentional SyntaxError surfaces as a single
     LintWarning at step_index=0.
  3. recipe.run with caller args → invokes the Python `run(ctx)` and
     returns the function's return value as the artifact body.
  4. Runtime exception inside `run(ctx)` → -32000 + exception_type +
     traceback in the response data.
  5. Negative-path: create without body in python-v1 mode rejected
     with -32602.

SKIP when ldbd's `describe.endpoints` reveals python-v1 format is not
supported (LDB_ENABLE_PYTHON=OFF at build).
"""
import json
import os
import select
import subprocess
import sys
import tempfile


def usage():
    sys.stderr.write("usage: test_recipe_python.py <ldbd>\n")
    sys.exit(2)


def main():
    if len(sys.argv) != 2:
        usage()
    ldbd = sys.argv[1]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n"); sys.exit(1)

    store_root = tempfile.mkdtemp(prefix="ldb_smoke_recipe_python_")
    try:
        env = dict(os.environ)
        env["LDB_STORE_ROOT"] = store_root
        env.setdefault("LLDB_LOG_LEVEL", "error")
        daemon = subprocess.Popen(
            [ldbd, "--stdio", "--log-level", "error"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env, text=True, bufsize=1,
        )

        next_id = [0]
        def call(method, params=None, timeout=15):
            next_id[0] += 1
            rid = f"r{next_id[0]}"
            req = {"jsonrpc": "2.0", "id": rid, "method": method,
                   "params": params or {}}
            daemon.stdin.write(json.dumps(req) + "\n")
            daemon.stdin.flush()
            ready, _, _ = select.select([daemon.stdout], [], [], timeout)
            if not ready:
                try: daemon.kill()
                except Exception: pass
                sys.stderr.write(
                    f"daemon hung on {method} after {timeout}s\n")
                sys.exit(1)
            line = daemon.stdout.readline()
            if not line:
                err = daemon.stderr.read() or ""
                sys.stderr.write(
                    f"daemon closed stdout (stderr was: {err})\n")
                sys.exit(1)
            return json.loads(line)

        failures = []
        def expect(cond, msg):
            if not cond:
                failures.append(msg)

        try:
            # ---- Skip-gate: python-v1 format must be supported ----
            r = call("describe.endpoints")
            assert r["ok"], r
            create_ep = next(
                (e for e in r["data"]["endpoints"]
                 if e["method"] == "recipe.create"), None)
            assert create_ep is not None
            # The schema enumerates supported `format` values.
            fmts = []
            try:
                fmts = create_ep["params_schema"]["properties"]["format"]["enum"]
            except (KeyError, TypeError):
                pass
            if "python-v1" not in fmts:
                print("SKIP: ldbd built without python-v1 support "
                      "(set LDB_ENABLE_PYTHON=ON to build)")
                return

            # ---- 1. Create a valid python-v1 recipe ----
            ok_body = (
                "def run(ctx):\n"
                "    return {\"echoed\": ctx.get(\"target_id\"),\n"
                "            \"label\": \"hello-\" + ctx.get(\"name\", \"?\")}\n"
            )
            r = call("recipe.create", {
                "name":   "py-echo",
                "format": "python-v1",
                "body":   ok_body,
            })
            expect(r["ok"], f"recipe.create py-echo: {r}")
            rid = r["data"]["recipe_id"]
            expect(rid > 0, f"recipe_id should be positive: {r['data']}")
            expect(r["data"].get("format") == "python-v1",
                   f"response should echo format: {r['data']}")

            # ---- 2a. Lint a valid python recipe → zero warnings ----
            r = call("recipe.lint", {"recipe_id": rid})
            expect(r["ok"], f"recipe.lint: {r}")
            expect(r["data"].get("warnings", "missing") == [],
                   f"lint of valid python recipe should be warning-free: "
                   f"{r['data']}")

            # ---- 2b. Lint a SyntaxError recipe ----
            bad_body = (
                "def run(ctx):\n"
                "    retrn ctx  # typo\n"
            )
            r = call("recipe.create", {
                "name":   "py-broken",
                "format": "python-v1",
                "body":   bad_body,
            })
            expect(r["ok"], f"create py-broken: {r}")
            bad_id = r["data"]["recipe_id"]
            r = call("recipe.lint", {"recipe_id": bad_id})
            expect(r["ok"], f"lint py-broken: {r}")
            warns = r["data"].get("warnings", [])
            expect(len(warns) >= 1,
                   f"SyntaxError should produce >=1 warning: {r['data']}")
            if warns:
                w0 = warns[0]
                expect(w0.get("step_index") == 0,
                       f"warning step_index should be 0: {w0}")
                expect("SyntaxError" in (w0.get("message") or "") or
                       "syntax" in (w0.get("message") or "").lower(),
                       f"warning should mention SyntaxError: {w0}")

            # ---- 3. Run with caller args ----
            r = call("recipe.run", {
                "recipe_id": rid,
                "args": {"target_id": 42, "name": "world"},
            })
            expect(r["ok"], f"recipe.run echo: {r}")
            data = r.get("data", {})
            result = data.get("result")
            expect(isinstance(result, dict),
                   f"recipe.run result should be dict: {data}")
            if isinstance(result, dict):
                expect(result.get("echoed") == 42,
                       f"echoed should be 42: {result}")
                expect(result.get("label") == "hello-world",
                       f"label should be hello-world: {result}")

            # ---- 4. Runtime exception path ----
            r = call("recipe.create", {
                "name":   "py-throws",
                "format": "python-v1",
                "body":   "def run(ctx):\n    raise ValueError('nope')\n",
            })
            expect(r["ok"], f"create py-throws: {r}")
            throws_id = r["data"]["recipe_id"]
            r = call("recipe.run", {"recipe_id": throws_id, "args": {}})
            expect(not r["ok"],
                   f"recipe.run with raise should fail: {r}")
            code = r.get("error", {}).get("code")
            expect(code == -32000,
                   f"runtime exception should map to -32000: code={code}")
            data = r.get("error", {}).get("data") or {}
            expect(data.get("exception_type") == "ValueError",
                   f"exception_type should be ValueError: data={data}")
            expect("nope" in (data.get("message") or ""),
                   f"message should contain 'nope': data={data}")

            # ---- 5. python-v1 create without body → -32602 ----
            r = call("recipe.create", {
                "name": "py-nobody", "format": "python-v1",
            })
            expect(not r["ok"], f"create without body should fail: {r}")
            expect(r.get("error", {}).get("code") == -32602,
                   f"missing body should be -32602: {r}")
        finally:
            try:
                daemon.stdin.close()
            except Exception:
                pass
            daemon.wait(timeout=5)

        if failures:
            sys.stderr.write("FAILURES:\n")
            for f in failures:
                sys.stderr.write(f"  - {f}\n")
            sys.exit(1)
        print("OK: recipe python-v1 smoke")
    finally:
        import shutil
        shutil.rmtree(store_root, ignore_errors=True)


if __name__ == "__main__":
    main()
