#!/usr/bin/env python3
"""End-to-end smoke for `describe.endpoints` (M5 §4.8).

Walks the JSON-RPC catalog and asserts every entry exposes the new
schema shape: method/summary/params_schema/returns_schema/requires_target/
requires_stopped/cost_hint, with cost_hint constrained to the documented
enum and at least 50 entries advertised.

Tightly scoped: this checks the *wire shape*, not the validity of the
schemas themselves (the unit test does that — pulling a JSON Schema
validator into the smoke harness is overkill).
"""
import json
import os
import subprocess
import sys
import tempfile


def usage():
    sys.stderr.write("usage: test_describe_endpoints.py <ldbd>\n")
    sys.exit(2)


def main():
    if len(sys.argv) != 2:
        usage()
    ldbd = sys.argv[1]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n")
        sys.exit(1)

    store_root = tempfile.mkdtemp(prefix="ldb_smoke_describe_")
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

        req = {"jsonrpc": "2.0", "id": "r1", "method": "describe.endpoints"}
        proc.stdin.write(json.dumps(req) + "\n")
        proc.stdin.flush()
        line = proc.stdout.readline()
        if not line:
            stderr = proc.stderr.read()
            sys.stderr.write(f"daemon closed stdout (stderr was: {stderr})\n")
            sys.exit(1)
        resp = json.loads(line)

        failures = []

        def expect(cond, msg):
            if not cond:
                failures.append(msg)

        expect(resp.get("ok"), f"describe.endpoints !ok: {resp}")
        eps = resp.get("data", {}).get("endpoints", [])
        expect(isinstance(eps, list),
               f"endpoints not array: {type(eps).__name__}")
        expect(len(eps) >= 50,
               f"expected >= 50 endpoints, got {len(eps)}")

        cost_hints = {"low", "medium", "high", "unbounded"}
        required_keys = {
            "method", "summary",
            "params_schema", "returns_schema",
            "requires_target", "requires_stopped",
            "cost_hint",
        }

        seen_methods = set()
        for e in eps:
            method = e.get("method", "<missing>")
            seen_methods.add(method)
            for k in required_keys:
                expect(k in e, f"{method}: missing key {k!r}")
            expect(isinstance(e.get("requires_target"), bool),
                   f"{method}: requires_target not bool")
            expect(isinstance(e.get("requires_stopped"), bool),
                   f"{method}: requires_stopped not bool")
            ch = e.get("cost_hint")
            expect(ch in cost_hints,
                   f"{method}: bogus cost_hint {ch!r}")
            ps = e.get("params_schema", {})
            rs = e.get("returns_schema", {})
            expect(isinstance(ps, dict) and ps.get("type") == "object",
                   f"{method}: params_schema not object-typed")
            expect(isinstance(rs, dict) and rs.get("type") == "object",
                   f"{method}: returns_schema not object-typed")

        # Spot-check a handful of well-known methods.
        for m in ["hello", "describe.endpoints", "target.open", "mem.read",
                  "probe.create", "observer.exec"]:
            expect(m in seen_methods, f"missing method: {m}")

        # describe.endpoints itself: low cost, no target needed.
        for e in eps:
            if e.get("method") == "describe.endpoints":
                expect(e.get("cost_hint") == "low",
                       f"describe.endpoints cost_hint should be 'low'")
                expect(e.get("requires_target") is False,
                       f"describe.endpoints requires_target should be false")
                expect(e.get("requires_stopped") is False,
                       f"describe.endpoints requires_stopped should be false")

        # frame.locals MUST flag requires_stopped.
        for e in eps:
            if e.get("method") == "frame.locals":
                expect(e.get("requires_stopped") is True,
                       f"frame.locals requires_stopped should be true")

        # JSON Schema draft tag should appear on at least one schema.
        draft = "https://json-schema.org/draft/2020-12/schema"
        saw_draft = any(
            e.get("params_schema", {}).get("$schema") == draft
            or e.get("returns_schema", {}).get("$schema") == draft
            for e in eps
        )
        expect(saw_draft, "no schema advertises JSON Schema 2020-12 draft")

        proc.stdin.close()
        proc.wait(timeout=5)

        if failures:
            for f in failures:
                sys.stderr.write(f"FAIL: {f}\n")
            sys.exit(1)
        print(f"OK: {len(eps)} endpoints with full schema shape")
    finally:
        try:
            proc.kill()
        except Exception:
            pass
        import shutil
        shutil.rmtree(store_root, ignore_errors=True)


if __name__ == "__main__":
    main()
