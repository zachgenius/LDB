#!/usr/bin/env python3
"""Smoke test for session.create / attach / detach / list / info.

End-to-end exercise of the session-log surface (M3 part 2):
  • describe.endpoints reports all five session.* methods.
  • Create two sessions; attach to one and emit a few RPCs.
  • info().call_count reflects the appends seen so far (>= the count
    of explicit calls; we don't pin the exact number because info()
    while-attached can either count itself or not depending on impl).
  • Detach. Emit more RPCs. info().call_count must NOT increase.
  • list() reports both sessions, newest-first.
  • Negative paths: attach with bad id → -32000; create with bad
    params → -32602.

Uses LDB_STORE_ROOT pointed at a per-test tmpdir — never touches ~/.ldb.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile


def usage():
    sys.stderr.write("usage: test_session.py <ldbd>\n")
    sys.exit(2)


def main():
    if len(sys.argv) != 2:
        usage()
    ldbd = sys.argv[1]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n"); sys.exit(1)

    store_root = tempfile.mkdtemp(prefix="ldb_smoke_session_")

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
            # --- describe.endpoints lists all five ---------------------
            r0 = call("describe.endpoints")
            expect(r0["ok"], f"describe.endpoints: {r0}")
            methods = {e["method"] for e in r0["data"]["endpoints"]}
            for m in ("session.create", "session.attach",
                      "session.detach", "session.list", "session.info"):
                expect(m in methods, f"missing endpoint: {m}")

            # --- create two sessions -----------------------------------
            c1 = call("session.create", {"name": "alpha"})
            expect(c1["ok"], f"session.create alpha: {c1}")
            sid_a = c1["data"]["id"]
            expect(len(sid_a) == 32, f"id should be 32-hex: {sid_a}")
            expect(c1["data"]["name"] == "alpha", f"name: {c1['data']}")
            expect(c1["data"]["created_at"] > 0,
                   f"created_at: {c1['data']}")
            expect(os.path.isfile(c1["data"]["path"]),
                   f"session db missing: {c1['data']['path']}")

            c2 = call("session.create", {"name": "beta",
                                          "target_id": "tgt-1"})
            expect(c2["ok"], f"session.create beta: {c2}")
            sid_b = c2["data"]["id"]
            expect(sid_b != sid_a, "ids must differ")

            # --- info immediately after create: 0 calls ---------------
            i_pre = call("session.info", {"id": sid_a})
            expect(i_pre["ok"], f"info pre-attach: {i_pre}")
            expect(i_pre["data"]["call_count"] == 0,
                   f"call_count should be 0 pre-attach: {i_pre['data']}")
            expect("last_call_at" not in i_pre["data"] or
                   i_pre["data"]["last_call_at"] is None,
                   f"last_call_at: {i_pre['data']}")

            # --- attach to alpha; emit RPCs ----------------------------
            at = call("session.attach", {"id": sid_a})
            expect(at["ok"], f"attach: {at}")
            expect(at["data"]["attached"] is True, f"attached: {at}")

            # Emit a few benign RPCs.
            call("hello")
            call("describe.endpoints")
            call("hello")

            i_mid = call("session.info", {"id": sid_a})
            expect(i_mid["ok"], f"info mid: {i_mid}")
            count_attached = i_mid["data"]["call_count"]
            # attach + hello + describe + hello = 4. info itself may or
            # may not be counted; require at least 4.
            expect(count_attached >= 4,
                   f"expected >=4 calls logged, got {count_attached}")

            # --- detach -------------------------------------------------
            dt = call("session.detach")
            expect(dt["ok"], f"detach: {dt}")
            expect(dt["data"]["detached"] is True, f"detached: {dt}")

            # Snapshot count after detach.
            i_post_detach = call("session.info", {"id": sid_a})
            expect(i_post_detach["ok"], f"info post-detach: {i_post_detach}")
            count_post_detach = i_post_detach["data"]["call_count"]

            # --- emit RPCs while detached: count must NOT increase ---
            call("hello")
            call("hello")
            call("describe.endpoints")

            i_final = call("session.info", {"id": sid_a})
            expect(i_final["ok"], f"info final: {i_final}")
            expect(i_final["data"]["call_count"] == count_post_detach,
                   "post-detach RPCs must not be logged: "
                   f"was {count_post_detach}, now "
                   f"{i_final['data']['call_count']}")

            # --- list reports both sessions ----------------------------
            lst = call("session.list")
            expect(lst["ok"], f"list: {lst}")
            expect(lst["data"]["total"] == 2,
                   f"expected 2 sessions: {lst['data']}")
            ids = [s["id"] for s in lst["data"]["sessions"]]
            expect(set(ids) == {sid_a, sid_b}, f"ids: {ids}")
            # Newest-first: beta was created after alpha.
            expect(ids[0] == sid_b,
                   f"newest-first: expected {sid_b} first, got {ids}")
            for s in lst["data"]["sessions"]:
                expect("call_count" in s,
                       f"list entry missing call_count: {s}")
                expect("path" in s, f"list entry missing path: {s}")

            # --- info on beta carries target_id ------------------------
            i_b = call("session.info", {"id": sid_b})
            expect(i_b["ok"], f"info beta: {i_b}")
            expect(i_b["data"].get("target_id") == "tgt-1",
                   f"target_id: {i_b['data']}")

            # --- error paths -------------------------------------------
            # attach with bogus id
            re1 = call("session.attach", {"id": "nonexistent"})
            expect(not re1["ok"] and
                   re1.get("error", {}).get("code") == -32000,
                   f"attach bogus: {re1}")

            # create with empty name
            re2 = call("session.create", {"name": ""})
            expect(not re2["ok"] and
                   re2.get("error", {}).get("code") == -32602,
                   f"create empty name: {re2}")

            # info with bogus id
            re3 = call("session.info", {"id": "nonexistent"})
            expect(not re3["ok"] and
                   re3.get("error", {}).get("code") == -32000,
                   f"info bogus: {re3}")

            # --- detach is idempotent (no-op when not attached) -------
            dt_again = call("session.detach")
            expect(dt_again["ok"], f"detach idempotent: {dt_again}")
            expect(dt_again["data"]["detached"] is False,
                   f"second detach should report detached=false: "
                   f"{dt_again['data']}")
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
        print("session smoke test PASSED")
    finally:
        shutil.rmtree(store_root, ignore_errors=True)


if __name__ == "__main__":
    main()
