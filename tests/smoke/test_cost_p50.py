#!/usr/bin/env python3
"""Smoke test for measured cost preview (post-V1 plan #4).

Verifies that describe.endpoints surfaces measured p50 token costs
alongside the static cost_hint for endpoints that have been called.
"""
import json
import os
import subprocess
import sys
import tempfile


def usage():
    sys.stderr.write("usage: test_cost_p50.py <ldbd>\n")
    sys.exit(2)


def main():
    if len(sys.argv) != 2:
        usage()
    ldbd = sys.argv[1]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n")
        sys.exit(1)

    store_root = tempfile.mkdtemp(prefix="ldb_smoke_cost_p50_")
    env = dict(os.environ)
    env["LDB_STORE_ROOT"] = store_root
    env.setdefault("LLDB_LOG_LEVEL", "error")

    proc = subprocess.Popen(
        [ldbd, "--stdio", "--log-level", "error"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
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
            sys.stderr.write(f"daemon closed stdout (stderr: {stderr})\n")
            sys.exit(1)
        return json.loads(line)

    failures = []

    def expect(cond, msg):
        if not cond:
            failures.append(msg)

    def find_endpoint(endpoints, method):
        for e in endpoints:
            if e.get("method") == method:
                return e
        return None

    try:
        # First call describe.endpoints to populate the catalog with
        # zero samples for every endpoint, then sample-drive a few.
        for _ in range(3):
            r = call("hello", {})
            expect(r["ok"], f"hello: {r}")

        desc = call("describe.endpoints", {"view": {"include_cost_stats": True}})
        expect(desc["ok"], f"describe.endpoints: {desc}")

        hello_e = find_endpoint(desc["data"]["endpoints"], "hello")
        expect(hello_e is not None, "hello not in describe.endpoints")
        # cost_n_samples should be >= 3 (the three hello calls above —
        # the describe.endpoints call doesn't itself add a hello sample).
        expect(hello_e["cost_n_samples"] >= 3,
               f"hello cost_n_samples too low: {hello_e}")
        # The hello response is small but non-empty; p50 should be a
        # small positive integer.
        expect("cost_p50_tokens" in hello_e,
               f"hello missing cost_p50_tokens: {hello_e}")
        expect(hello_e["cost_p50_tokens"] > 0,
               f"hello p50 should be positive: {hello_e}")
        # The static cost_hint must still be present (backward compat).
        expect("cost_hint" in hello_e, f"hello missing cost_hint: {hello_e}")

        # An uncalled endpoint should report zero samples and omit p50.
        uncalled = find_endpoint(desc["data"]["endpoints"], "mem.search")
        expect(uncalled is not None, "mem.search not in describe.endpoints")
        expect(uncalled["cost_n_samples"] == 0,
               f"mem.search cost_n_samples nonzero: {uncalled}")
        expect("cost_p50_tokens" not in uncalled,
               f"mem.search shouldn't have p50 with zero samples: "
               f"{uncalled}")

        # Calling describe.endpoints itself adds a sample for it.
        # (This call we're about to make is the one that gets counted
        # for the NEXT describe.endpoints call.)
        desc2 = call("describe.endpoints", {"view": {"include_cost_stats": True}})
        desc_e = find_endpoint(desc2["data"]["endpoints"],
                                "describe.endpoints")
        expect(desc_e is not None, "describe.endpoints self-entry missing")
        # We've now made one prior describe.endpoints call; this one
        # observes the sample left by the previous call.
        expect(desc_e["cost_n_samples"] >= 1,
               f"describe.endpoints cost_n_samples should reflect prior "
               f"call: {desc_e}")
        expect("cost_p50_tokens" in desc_e,
               f"describe.endpoints missing p50: {desc_e}")
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        proc.wait(timeout=10)
        import shutil
        shutil.rmtree(store_root, ignore_errors=True)

    if failures:
        for f in failures:
            sys.stderr.write(f"FAIL: {f}\n")
        sys.exit(1)
    print("cost_p50 smoke test PASSED")


if __name__ == "__main__":
    main()
