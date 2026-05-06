#!/usr/bin/env python3
"""Smoke test for observer.net.igmp (M4 §4.6 closeout).

Drives the local-dispatch happy path. The describe-endpoints
assertion is unconditional; live cases SKIP cleanly when /proc/net/igmp
is missing.
"""
import json
import os
import subprocess
import sys


def usage():
    sys.stderr.write("usage: test_observer_igmp.py <ldbd>\n")
    sys.exit(2)


def main():
    if len(sys.argv) != 2:
        usage()
    ldbd = sys.argv[1]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n"); sys.exit(1)

    env = dict(os.environ)
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
            stderr_data = proc.stderr.read()
            sys.stderr.write(
                f"daemon closed stdout (stderr was: {stderr_data})\n")
            sys.exit(1)
        return json.loads(line)

    failures = []
    def expect(cond, msg):
        if not cond: failures.append(msg)

    try:
        # describe.endpoints must include observer.net.igmp.
        r0 = call("describe.endpoints")
        expect(r0["ok"], f"describe.endpoints: {r0}")
        methods = {e["method"] for e in r0["data"]["endpoints"]}
        expect("observer.net.igmp" in methods,
               "missing endpoint observer.net.igmp")

        # Live case — gate on /proc/net/igmp existence.
        if not os.path.exists("/proc/net/igmp"):
            print("observer.net.igmp smoke test PASSED "
                  "(live cases SKIPPED — no /proc/net/igmp)")
            return

        r = call("observer.net.igmp", {})
        expect(r["ok"], f"observer.net.igmp: {r}")
        if r["ok"]:
            d = r["data"]
            expect("groups" in d and "total" in d, f"shape: {d}")
            expect(d["total"] == len(d["groups"]),
                   f"total/len mismatch: {d['total']} vs {len(d['groups'])}")
            # lo always has at least one membership on Linux.
            saw_lo = False
            for g in d["groups"]:
                expect({"idx", "device", "addresses"}.issubset(g.keys()),
                       f"group shape: {g}")
                if g["device"] == "lo":
                    saw_lo = True
                    for a in g["addresses"]:
                        expect({"address", "users", "timer"}.issubset(a.keys()),
                               f"addr shape: {a}")
            expect(saw_lo, "no lo interface in igmp groups")

            # view: limit applies.
            r_lim = call("observer.net.igmp",
                         {"view": {"limit": 1, "offset": 0}})
            expect(r_lim["ok"], f"observer.net.igmp view: {r_lim}")
            if r_lim["ok"]:
                expect(len(r_lim["data"]["groups"]) <= 1,
                       f"view limit: {len(r_lim['data']['groups'])}")
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
    print("observer.net.igmp smoke test PASSED")


if __name__ == "__main__":
    main()
