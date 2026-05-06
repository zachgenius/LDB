#!/usr/bin/env python3
"""Smoke test for session.diff (Tier 3 §11).

End-to-end:
  • describe.endpoints reports session.diff with the expected schema
    shape (params requires session_a + session_b; cost_hint=unbounded).
  • Drive two sessions through ldbd: same prefix, B adds one extra rpc,
    A has one rpc that B doesn't.
  • session.diff reports the expected counts in `summary` and matching
    entries in `entries`.
  • view.limit slices entries; total stays the count of all entries.
  • Negative paths: bogus session id → -32000; missing param → -32602.

Uses LDB_STORE_ROOT pointed at a per-test tmpdir.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile


def usage():
    sys.stderr.write("usage: test_session_diff.py <ldbd>\n")
    sys.exit(2)


def main():
    if len(sys.argv) != 2:
        usage()
    ldbd = sys.argv[1]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n"); sys.exit(1)

    store_root = tempfile.mkdtemp(prefix="ldb_smoke_diff_")

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
            # --- describe.endpoints reports session.diff ---------------
            d_eps = call("describe.endpoints")
            expect(d_eps["ok"], f"describe.endpoints: {d_eps}")
            diff_ep = None
            for e in d_eps["data"]["endpoints"]:
                if e.get("method") == "session.diff":
                    diff_ep = e; break
            expect(diff_ep is not None, "session.diff not in catalog")
            if diff_ep:
                req_keys = diff_ep["params_schema"].get("required", [])
                expect("session_a" in req_keys,
                       f"session_a not required: {req_keys}")
                expect("session_b" in req_keys,
                       f"session_b not required: {req_keys}")
                expect(diff_ep.get("cost_hint") == "unbounded",
                       f"cost_hint: {diff_ep.get('cost_hint')}")

            # --- session A: hello, hello, describe, hello -------------
            ca = call("session.create", {"name": "alpha"})
            expect(ca["ok"], f"create alpha: {ca}")
            sid_a = ca["data"]["id"]

            at_a = call("session.attach", {"id": sid_a})
            expect(at_a["ok"], f"attach alpha: {at_a}")
            call("hello")
            call("hello")
            call("describe.endpoints")
            call("hello")
            call("session.detach")

            # --- session B: hello, describe, hello (one fewer hello) ---
            cb = call("session.create", {"name": "beta"})
            expect(cb["ok"], f"create beta: {cb}")
            sid_b = cb["data"]["id"]

            at_b = call("session.attach", {"id": sid_b})
            expect(at_b["ok"], f"attach beta: {at_b}")
            call("hello")
            call("describe.endpoints")
            call("hello")
            # One extra unique call only in B.
            call("hello", {"protocol_min": "1.0"})
            call("session.detach")

            # --- session.diff(A, B) ------------------------------------
            diff = call("session.diff",
                        {"session_a": sid_a, "session_b": sid_b})
            expect(diff["ok"], f"diff: {diff}")
            data = diff["data"]
            for k in ("summary", "entries", "total"):
                expect(k in data, f"missing top-level key {k}: {data}")

            s = data["summary"]
            for k in ("total_a", "total_b", "added", "removed",
                      "common", "diverged"):
                expect(k in s, f"summary missing {k}: {s}")

            # Sanity: total_a >= 4 (attach + 3 work calls + detach = 5
            # rows; the attach record's params carry sid_a so it diverges
            # from B's attach row, which carries sid_b — those won't
            # align as common, but they will appear as distinct rows in
            # both totals).
            expect(s["total_a"] >= 4,
                   f"total_a should be >= 4, got {s['total_a']}")
            expect(s["total_b"] >= 4,
                   f"total_b should be >= 4, got {s['total_b']}")

            # The unique "hello protocol_min=1.0" in B is the only entry
            # truly distinct in B vs A; expect at least one added.
            expect(s["added"] >= 1,
                   f"expected at least one added: {s}")

            # Counts must match the entries[] tally.
            kind_counts = {"common": 0, "added": 0,
                           "removed": 0, "diverged": 0}
            for e in data["entries"]:
                expect("kind" in e, f"entry missing kind: {e}")
                kind_counts[e["kind"]] = kind_counts.get(e["kind"], 0) + 1
                expect("method" in e, f"entry missing method: {e}")
                expect("params_hash" in e, f"entry missing params_hash: {e}")

            for k in ("common", "added", "removed", "diverged"):
                expect(s[k] == kind_counts.get(k, 0),
                       f"summary[{k}] ({s[k]}) != "
                       f"counted entries ({kind_counts.get(k, 0)})")

            # total in the wire shape == sum of all kinds.
            total = data["total"]
            expect(total == sum(kind_counts.values()),
                   f"total ({total}) != sum of kinds "
                   f"({sum(kind_counts.values())})")

            # --- view.limit=2 → 2 entries; total still full -----------
            sliced = call("session.diff",
                          {"session_a": sid_a, "session_b": sid_b,
                           "view": {"limit": 2}})
            expect(sliced["ok"], f"diff sliced: {sliced}")
            expect(len(sliced["data"]["entries"]) == 2,
                   f"limit=2 should give 2 entries, got "
                   f"{len(sliced['data']['entries'])}")
            expect(sliced["data"]["total"] == total,
                   f"sliced.total ({sliced['data']['total']}) != "
                   f"unsliced.total ({total})")

            # --- error: bogus session id → -32000 ---------------------
            bad = call("session.diff",
                       {"session_a": sid_a, "session_b": "nope"})
            expect(not bad["ok"], f"bogus diff should fail: {bad}")
            expect(bad.get("error", {}).get("code") == -32000,
                   f"bogus diff code: {bad.get('error')}")

            # --- error: missing param → -32602 ------------------------
            missing = call("session.diff", {"session_a": sid_a})
            expect(not missing["ok"], f"missing param: {missing}")
            expect(missing.get("error", {}).get("code") == -32602,
                   f"missing param code: {missing.get('error')}")
        finally:
            try: proc.stdin.close()
            except Exception: pass
            proc.wait(timeout=10)

        if failures:
            for f in failures:
                sys.stderr.write(f"FAIL: {f}\n")
            sys.exit(1)
        print("session.diff smoke test PASSED")
    finally:
        shutil.rmtree(store_root, ignore_errors=True)


if __name__ == "__main__":
    main()
