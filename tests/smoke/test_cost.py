#!/usr/bin/env python3
"""Smoke test for `_cost` preview metadata (M5 part 1, plan §3.2).

Drives a few representative methods through the running daemon and
asserts:

  * every ok:true response carries `_cost` with `bytes` + `tokens_est`.
  * an error response (-32601 method-not-found) does NOT carry `_cost`.
  * `bytes` matches the actual serialized length of `data`.
  * `tokens_est == ceil(bytes / 4)`.
  * for an array-returning endpoint (describe.endpoints) `items` equals
    the number of elements in the returned array, and is large
    (the catalog has dozens of entries).
"""
import json
import math
import os
import subprocess
import sys


def usage():
    sys.stderr.write("usage: test_cost.py <ldbd>\n")
    sys.exit(2)


def main():
    if len(sys.argv) != 2:
        usage()
    ldbd = sys.argv[1]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n")
        sys.exit(1)

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
            stderr_data = proc.stderr.read()
            sys.stderr.write(
                f"daemon closed stdout (stderr was: {stderr_data})\n")
            sys.exit(1)
        return json.loads(line)

    failures = []

    def expect(cond, msg):
        if not cond:
            failures.append(msg)

    try:
        # --- ok response: simple object data (hello) -------------------
        r_hello = call("hello")
        expect(r_hello["ok"], f"hello not ok: {r_hello}")
        expect("_cost" in r_hello, f"hello missing _cost: {r_hello}")
        cost = r_hello.get("_cost", {})
        expect("bytes" in cost and "tokens_est" in cost,
               f"hello _cost shape: {cost}")
        # bytes is exact length of serialized data.
        data_dump = json.dumps(r_hello["data"], separators=(",", ":"))
        expect(cost["bytes"] == len(data_dump),
               f"hello _cost.bytes mismatch: "
               f"reported={cost['bytes']} actual={len(data_dump)}")
        # tokens_est = ceil(bytes/4)
        expect(cost["tokens_est"] == math.ceil(cost["bytes"] / 4),
               f"hello tokens_est: bytes={cost['bytes']} "
               f"tokens={cost['tokens_est']}")

        # --- ok response: array-returning endpoint ---------------------
        r_endpoints = call("describe.endpoints")
        expect(r_endpoints["ok"], f"describe not ok: {r_endpoints}")
        expect("_cost" in r_endpoints,
               f"describe missing _cost: {r_endpoints}")
        c2 = r_endpoints.get("_cost", {})
        expect("items" in c2,
               f"describe _cost should have items: {c2}")
        expect(c2.get("items") == len(r_endpoints["data"]["endpoints"]),
               f"describe items mismatch: cost.items={c2.get('items')} "
               f"endpoints.len={len(r_endpoints['data']['endpoints'])}")
        # Catalog is large (>30 endpoints by M4 close).
        expect(c2.get("items", 0) >= 30,
               f"describe items unexpectedly small: {c2.get('items')}")
        # bytes is non-trivial for a long catalog.
        expect(c2.get("bytes", 0) > 1000,
               f"describe bytes too small: {c2.get('bytes')}")

        # --- error response: must NOT carry _cost ----------------------
        r_err = call("no.such.method")
        expect(not r_err["ok"], f"expected error: {r_err}")
        expect(r_err.get("error", {}).get("code") == -32601,
               f"expected -32601: {r_err}")
        expect("_cost" not in r_err,
               f"error response should not carry _cost: {r_err}")
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
    print("cost smoke test PASSED")


if __name__ == "__main__":
    main()
