#!/usr/bin/env python3
"""Smoke test for multi-binary inventory (Tier 3 §9).

End-to-end:
  • describe.endpoints reports target.list, target.label, session.targets.
  • Open two real fixtures (structs + sleeper); label each.
  • target.list returns 2 with labels, paths, triples, has_process=False,
    snapshot present.
  • target.label conflict surfaces as -32602.
  • Attach a session, drive a few RPCs against each target, detach.
  • session.targets returns two buckets with correct counts and the
    enriched live label per target.
  • close_target drops the label (target.label can re-take the freed
    name).

Uses LDB_STORE_ROOT pointed at a per-test tmpdir — never touches ~/.ldb.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile


def usage():
    sys.stderr.write(
        "usage: test_multi_binary.py <ldbd> <structs_bin> <sleeper_bin>\n")
    sys.exit(2)


def main():
    if len(sys.argv) != 4:
        usage()
    ldbd, structs_bin, sleeper_bin = sys.argv[1:4]
    for p in (ldbd, structs_bin, sleeper_bin):
        if not os.access(p, os.X_OK):
            sys.stderr.write(f"not executable: {p}\n"); sys.exit(1)

    store_root = tempfile.mkdtemp(prefix="ldb_smoke_multi_bin_")

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
            # --- describe.endpoints carries the three new methods ------
            d = call("describe.endpoints")
            expect(d["ok"], f"describe.endpoints: {d}")
            methods = {e["method"] for e in d["data"]["endpoints"]}
            for m in ("target.list", "target.label", "session.targets"):
                expect(m in methods, f"missing endpoint: {m}")

            # --- open two targets --------------------------------------
            o1 = call("target.open", {"path": structs_bin})
            expect(o1["ok"], f"target.open structs: {o1}")
            tid_a = o1["data"]["target_id"]

            o2 = call("target.open", {"path": sleeper_bin})
            expect(o2["ok"], f"target.open sleeper: {o2}")
            tid_b = o2["data"]["target_id"]
            expect(tid_a != tid_b, "target_ids must differ")

            # --- target.list before labels -----------------------------
            l_pre = call("target.list")
            expect(l_pre["ok"], f"target.list: {l_pre}")
            expect(l_pre["data"]["total"] == 2,
                   f"expected 2 targets: {l_pre['data']}")
            for t in l_pre["data"]["targets"]:
                expect("target_id" in t, f"missing target_id: {t}")
                expect("triple" in t, f"missing triple: {t}")
                expect("has_process" in t, f"missing has_process: {t}")
                expect(t["has_process"] is False,
                       f"unexpected has_process=True: {t}")
                expect("path" in t, f"missing path: {t}")
                expect("label" not in t,
                       f"unexpected label pre-label: {t}")

            # --- label each target -------------------------------------
            la = call("target.label", {"target_id": tid_a,
                                        "label": "structs_bin"})
            expect(la["ok"], f"target.label structs: {la}")
            expect(la["data"]["label"] == "structs_bin",
                   f"label echo: {la['data']}")

            lb = call("target.label", {"target_id": tid_b,
                                        "label": "sleeper_bin"})
            expect(lb["ok"], f"target.label sleeper: {lb}")

            # --- target.list after labels ------------------------------
            l_post = call("target.list")
            expect(l_post["ok"], f"target.list post: {l_post}")
            by_id = {t["target_id"]: t for t in l_post["data"]["targets"]}
            expect(by_id[tid_a].get("label") == "structs_bin",
                   f"label A: {by_id.get(tid_a)}")
            expect(by_id[tid_b].get("label") == "sleeper_bin",
                   f"label B: {by_id.get(tid_b)}")
            # path matches the executable we opened.
            expect(by_id[tid_a]["path"] == structs_bin,
                   f"path A: {by_id[tid_a]}")
            expect(by_id[tid_b]["path"] == sleeper_bin,
                   f"path B: {by_id[tid_b]}")

            # --- conflict on label -------------------------------------
            conflict = call("target.label", {"target_id": tid_b,
                                              "label": "structs_bin"})
            expect(not conflict["ok"], f"conflict ok?: {conflict}")
            expect(conflict.get("error", {}).get("code") == -32602,
                   f"conflict code: {conflict}")
            # B still owns its old label (conflict didn't perturb it).
            l_after_conflict = call("target.list")
            by_id2 = {t["target_id"]: t
                      for t in l_after_conflict["data"]["targets"]}
            expect(by_id2[tid_b].get("label") == "sleeper_bin",
                   f"B label after conflict: {by_id2[tid_b]}")

            # --- self-relabel with same string is a no-op --------------
            same = call("target.label", {"target_id": tid_a,
                                          "label": "structs_bin"})
            expect(same["ok"], f"self-relabel: {same}")

            # --- session inventory -------------------------------------
            cs = call("session.create", {"name": "multi-binary"})
            expect(cs["ok"], f"session.create: {cs}")
            sid = cs["data"]["id"]

            at = call("session.attach", {"id": sid})
            expect(at["ok"], f"session.attach: {at}")

            # 3 calls against A, 1 against B.
            call("module.list", {"target_id": tid_a})
            call("module.list", {"target_id": tid_b})
            call("module.list", {"target_id": tid_a})
            call("module.list", {"target_id": tid_a})

            dt = call("session.detach")
            expect(dt["ok"], f"session.detach: {dt}")

            st = call("session.targets", {"session_id": sid})
            expect(st["ok"], f"session.targets: {st}")
            expect(st["data"]["total"] == 2,
                   f"expected 2 buckets: {st['data']}")
            buckets = {b["target_id"]: b for b in st["data"]["targets"]}
            expect(tid_a in buckets and tid_b in buckets,
                   f"bucket ids: {list(buckets)}")
            expect(buckets[tid_a]["call_count"] == 3,
                   f"A count: {buckets[tid_a]}")
            expect(buckets[tid_b]["call_count"] == 1,
                   f"B count: {buckets[tid_b]}")
            expect(buckets[tid_a]["label"] == "structs_bin",
                   f"A label: {buckets[tid_a]}")
            expect(buckets[tid_b]["label"] == "sleeper_bin",
                   f"B label: {buckets[tid_b]}")
            expect(buckets[tid_a]["first_seq"] <= buckets[tid_a]["last_seq"],
                   f"A seq window: {buckets[tid_a]}")

            # --- close drops the label so it becomes available --------
            cl = call("target.close", {"target_id": tid_a})
            expect(cl["ok"], f"target.close A: {cl}")

            # B can now claim "structs_bin" — A's old name is freed.
            relabel = call("target.label", {"target_id": tid_b,
                                              "label": "structs_bin"})
            expect(relabel["ok"],
                   f"reclaim label after close: {relabel}")

            # session.targets after close: A's bucket loses the label
            # (label is enriched live; closed target → no label).
            st_after = call("session.targets", {"session_id": sid})
            buckets_after = {b["target_id"]: b
                             for b in st_after["data"]["targets"]}
            expect("label" not in buckets_after[tid_a],
                   f"closed-target bucket should have no label: "
                   f"{buckets_after[tid_a]}")

            # --- error paths -------------------------------------------
            bad_session = call("session.targets",
                               {"session_id": "nonexistent"})
            expect(not bad_session["ok"] and
                   bad_session.get("error", {}).get("code") == -32000,
                   f"bad session: {bad_session}")

            missing_label = call("target.label", {"target_id": tid_b})
            expect(not missing_label["ok"] and
                   missing_label.get("error", {}).get("code") == -32602,
                   f"missing label: {missing_label}")

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
        print("multi_binary smoke test PASSED")
    finally:
        shutil.rmtree(store_root, ignore_errors=True)


if __name__ == "__main__":
    main()
