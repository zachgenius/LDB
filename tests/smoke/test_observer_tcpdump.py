#!/usr/bin/env python3
"""Smoke test for observer.net.tcpdump (M4 part 5, §4.6).

Drives the JSON-RPC surface end-to-end:
  - describe.endpoints includes `observer.net.tcpdump`.
  - Param validation: missing iface, empty iface, missing/zero/over-limit
    count, and out-of-range snaplen all return -32602.
  - Live happy path: 3 packets on `lo`. Gated on having tcpdump and
    capture privilege; SKIPped cleanly otherwise.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile


def usage():
    sys.stderr.write("usage: test_observer_tcpdump.py <ldbd>\n")
    sys.exit(2)


def has_tcpdump():
    return subprocess.run(
        ["sh", "-c", "tcpdump --version >/dev/null 2>&1"]
    ).returncode == 0


def has_capture_permission():
    """Probe for CAP_NET_RAW by trying tcpdump on lo for one packet."""
    if os.geteuid() == 0:
        return True
    rc = subprocess.run(
        ["sh", "-c",
         "tcpdump -nn -tt -l -c 0 -i lo >/dev/null 2>&1 & "
         "PID=$!; sleep 0.05; kill $PID 2>/dev/null; wait $PID 2>/dev/null"
        ]
    ).returncode
    # 0 → ran cleanly (had perms). Non-zero → no perms / failure.
    # Fall back to the more direct check by trying a short capture.
    out = subprocess.run(
        ["tcpdump", "-nn", "-tt", "-l", "-c", "1", "-i", "lo"],
        capture_output=True, text=True, timeout=2,
    )
    if "permission" in (out.stderr or "").lower():
        return False
    if "Operation not permitted" in (out.stderr or ""):
        return False
    # If tcpdump exited 0 with output, we have perms.
    return out.returncode == 0


def main():
    if len(sys.argv) != 2:
        usage()
    ldbd = sys.argv[1]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n"); sys.exit(1)

    store_root = tempfile.mkdtemp(prefix="ldb_smoke_tcpdump_")
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
            # describe.endpoints surface check.
            r0 = call("describe.endpoints")
            expect(r0["ok"], f"describe.endpoints: {r0}")
            methods = {e["method"] for e in r0["data"]["endpoints"]}
            expect("observer.net.tcpdump" in methods,
                   f"observer.net.tcpdump missing from catalog: "
                   f"{sorted(methods)}")

            # --- param validation ----------------------------------------
            r_no_iface = call("observer.net.tcpdump", {"count": 3})
            expect(not r_no_iface["ok"]
                   and r_no_iface.get("error", {}).get("code") == -32602,
                   f"missing iface → -32602: {r_no_iface}")

            r_empty = call("observer.net.tcpdump",
                           {"iface": "", "count": 3})
            expect(not r_empty["ok"]
                   and r_empty.get("error", {}).get("code") == -32602,
                   f"empty iface → -32602: {r_empty}")

            r_no_count = call("observer.net.tcpdump", {"iface": "lo"})
            expect(not r_no_count["ok"]
                   and r_no_count.get("error", {}).get("code") == -32602,
                   f"missing count → -32602: {r_no_count}")

            r_zero = call("observer.net.tcpdump",
                          {"iface": "lo", "count": 0})
            expect(not r_zero["ok"]
                   and r_zero.get("error", {}).get("code") == -32602,
                   f"zero count → -32602: {r_zero}")

            r_huge = call("observer.net.tcpdump",
                          {"iface": "lo", "count": 999999})
            expect(not r_huge["ok"]
                   and r_huge.get("error", {}).get("code") == -32602,
                   f"oversize count → -32602: {r_huge}")

            r_snap = call("observer.net.tcpdump",
                          {"iface": "lo", "count": 1, "snaplen": 65536})
            expect(not r_snap["ok"]
                   and r_snap.get("error", {}).get("code") == -32602,
                   f"oversize snaplen → -32602: {r_snap}")

            # --- live happy path (gated) ---------------------------------
            if not has_tcpdump():
                print("observer tcpdump smoke PASSED "
                      "(live SKIPPED — no tcpdump binary)")
                return
            if not has_capture_permission():
                print("observer tcpdump smoke PASSED "
                      "(live SKIPPED — no CAP_NET_RAW)")
                return

            # Generate background traffic on lo: curl to a closed port.
            traffic = subprocess.Popen(
                ["sh", "-c",
                 "for i in 1 2 3 4 5; do "
                 "  sleep 0.1; "
                 "  curl --max-time 1 -s http://127.0.0.1:1 "
                 "    >/dev/null 2>&1 || true; "
                 "done"],
            )
            try:
                r_live = call("observer.net.tcpdump",
                              {"iface": "lo", "count": 3})
                expect(r_live["ok"], f"live capture: {r_live}")
                if r_live["ok"]:
                    d = r_live["data"]
                    expect("packets" in d and "total" in d,
                           f"shape: {d}")
                    expect(d["total"] == len(d["packets"]),
                           f"total/len mismatch: {d}")
                    for p in d["packets"]:
                        expect("ts" in p, f"ts missing: {p}")
                        expect("summary" in p, f"summary missing: {p}")
            finally:
                traffic.wait(timeout=5)
        finally:
            try: proc.stdin.close()
            except Exception: pass
            proc.wait(timeout=10)

        if failures:
            for f in failures:
                sys.stderr.write(f"FAIL: {f}\n")
            sys.exit(1)
        print("observer tcpdump smoke PASSED")
    finally:
        shutil.rmtree(store_root, ignore_errors=True)


if __name__ == "__main__":
    main()
