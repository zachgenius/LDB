#!/usr/bin/env python3
"""Smoke test for probe.create / probe.events / probe.list /
probe.disable / probe.enable / probe.delete (M3 part 3).

Drives the full probe surface end-to-end against the structs fixture:
opens the binary, creates a probe on a function reliably hit by main,
launches the inferior, pulls events, lists probes, and deletes. Also
exercises one error path.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time


def usage():
    sys.stderr.write("usage: test_probe.py <ldbd> <fixture>\n")
    sys.exit(2)


def main():
    if len(sys.argv) != 3:
        usage()
    ldbd = sys.argv[1]
    fixture = sys.argv[2]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n"); sys.exit(1)
    if not os.access(fixture, os.X_OK):
        sys.stderr.write(f"fixture not executable: {fixture}\n"); sys.exit(1)

    store_root = tempfile.mkdtemp(prefix="ldb_smoke_probe_")

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
            # describe.endpoints must list all six probe.* methods.
            r0 = call("describe.endpoints")
            expect(r0["ok"], f"describe.endpoints: {r0}")
            methods = {e["method"] for e in r0["data"]["endpoints"]}
            for m in ("probe.create", "probe.events", "probe.list",
                      "probe.disable", "probe.enable", "probe.delete"):
                expect(m in methods, f"missing endpoint: {m}")

            # Open the structs fixture.
            ro = call("target.open", {"path": fixture})
            expect(ro["ok"], f"target.open: {ro}")
            target_id = ro["data"]["target_id"]

            # Sanity: confirm point2_distance_sq is in the symbol table.
            rs = call("symbol.find", {"target_id": target_id,
                                      "name": "point2_distance_sq",
                                      "kind": "function"})
            expect(rs["ok"], f"symbol.find: {rs}")
            expect(len(rs["data"]["matches"]) >= 1,
                   f"point2_distance_sq missing: {rs}")

            # --- create probe ----------------------------------------
            rc = call("probe.create", {
                "target_id": target_id,
                "kind": "lldb_breakpoint",
                "where": {"function": "point2_distance_sq"},
                "action": "log_and_continue",
            })
            expect(rc["ok"], f"probe.create: {rc}")
            probe_id = rc["data"]["probe_id"]
            expect(probe_id.startswith("p"),
                   f"probe_id format: {probe_id!r}")

            # --- launch inferior --------------------------------------
            # stop_at_entry=false → run to completion (or to next stop).
            # The probe fires (auto-continues), main returns, inferior
            # exits. process.launch is synchronous (SetAsync(false)).
            rl = call("process.launch", {"target_id": target_id,
                                         "stop_at_entry": False})
            expect(rl["ok"], f"process.launch: {rl}")
            # Bounded settle for the LLDB callback bookkeeping.
            time.sleep(0.1)

            # --- events -----------------------------------------------
            re = call("probe.events", {"probe_id": probe_id})
            expect(re["ok"], f"probe.events: {re}")
            events = re["data"]["events"]
            expect(len(events) >= 1,
                   f"expected ≥1 event, got {len(events)}: {re}")
            if events:
                e0 = events[0]
                expect(e0["probe_id"] == probe_id,
                       f"probe_id field: {e0}")
                expect(e0["hit_seq"] == 1, f"hit_seq: {e0}")
                expect(isinstance(e0["pc"], str) and
                       e0["pc"].startswith("0x"),
                       f"pc must be hex string: {e0}")
                expect(e0["tid"] != 0, f"tid: {e0}")
                expect("site" in e0 and "function" in e0["site"],
                       f"site: {e0}")
                expect("registers" in e0, f"registers field: {e0}")
                expect("memory" in e0, f"memory field: {e0}")

            # next_since should be max hit_seq returned.
            expect(re["data"]["next_since"] >= 1,
                   f"next_since: {re['data']}")

            # since=N pagination — ask for events after the latest hit_seq:
            # should be empty.
            latest = max(e["hit_seq"] for e in events) if events else 0
            re2 = call("probe.events", {"probe_id": probe_id,
                                        "since": latest})
            expect(re2["ok"], f"probe.events since: {re2}")
            expect(len(re2["data"]["events"]) == 0,
                   f"since=latest should be empty: {re2}")

            # --- list -------------------------------------------------
            rl2 = call("probe.list")
            expect(rl2["ok"], f"probe.list: {rl2}")
            probes = rl2["data"]["probes"]
            expect(len(probes) == 1, f"probe.list count: {probes}")
            if probes:
                expect(probes[0]["probe_id"] == probe_id,
                       f"probe id: {probes[0]}")
                expect(probes[0]["hit_count"] >= 1,
                       f"hit_count: {probes[0]}")
                expect(probes[0]["enabled"] is True,
                       f"enabled: {probes[0]}")
                expect(probes[0]["where_expr"] == "point2_distance_sq",
                       f"where_expr: {probes[0]}")

            # --- disable / enable round-trip --------------------------
            rdi = call("probe.disable", {"probe_id": probe_id})
            expect(rdi["ok"] and rdi["data"]["enabled"] is False,
                   f"probe.disable: {rdi}")

            ren = call("probe.enable", {"probe_id": probe_id})
            expect(ren["ok"] and ren["data"]["enabled"] is True,
                   f"probe.enable: {ren}")

            # --- delete -----------------------------------------------
            rd = call("probe.delete", {"probe_id": probe_id})
            expect(rd["ok"] and rd["data"]["deleted"] is True,
                   f"probe.delete: {rd}")

            # post-delete list is empty.
            rl3 = call("probe.list")
            expect(rl3["ok"] and rl3["data"]["total"] == 0,
                   f"post-delete list: {rl3}")

            # Querying a deleted probe's events should fail with -32000.
            re3 = call("probe.events", {"probe_id": probe_id})
            expect(not re3["ok"] and
                   re3.get("error", {}).get("code") == -32000,
                   f"events on deleted probe: {re3}")

            # --- error paths ------------------------------------------
            # Unknown action → -32602.
            rer = call("probe.create", {
                "target_id": target_id,
                "kind": "lldb_breakpoint",
                "where": {"function": "main"},
                "action": "no_such_action",
            })
            expect(not rer["ok"] and
                   rer.get("error", {}).get("code") == -32602,
                   f"unknown action: {rer}")

            # Bad target_id → -32000 (backend error).
            rbt = call("probe.create", {
                "target_id": 99999,
                "kind": "lldb_breakpoint",
                "where": {"function": "main"},
            })
            expect(not rbt["ok"] and
                   rbt.get("error", {}).get("code") == -32000,
                   f"bad target_id: {rbt}")

            # Missing where → -32602.
            rmw = call("probe.create", {
                "target_id": target_id,
                "kind": "lldb_breakpoint",
            })
            expect(not rmw["ok"] and
                   rmw.get("error", {}).get("code") == -32602,
                   f"missing where: {rmw}")

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
        print("probe smoke test PASSED")
    finally:
        shutil.rmtree(store_root, ignore_errors=True)


if __name__ == "__main__":
    main()
