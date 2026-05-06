#!/usr/bin/env python3
"""Smoke test for observer.proc.* / observer.net.sockets (M4 part 3).

Drives the full RPC surface end-to-end with no `host` param (local
dispatch). Requires /proc to be present — SKIPs the live cases on
macOS / BSD; the describe-endpoints / param-validation cases run
unconditionally.
"""
import json
import os
import subprocess
import sys


def usage():
    sys.stderr.write("usage: test_observer.py <ldbd>\n")
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
        # describe.endpoints must list all four methods.
        r0 = call("describe.endpoints")
        expect(r0["ok"], f"describe.endpoints: {r0}")
        methods = {e["method"] for e in r0["data"]["endpoints"]}
        for m in ("observer.proc.fds", "observer.proc.maps",
                  "observer.proc.status", "observer.net.sockets"):
            expect(m in methods, f"missing endpoint: {m}")

        # --- param validation -------------------------------------------
        r_no_pid = call("observer.proc.fds", {})
        expect(not r_no_pid["ok"] and
               r_no_pid.get("error", {}).get("code") == -32602,
               f"missing pid: {r_no_pid}")

        r_neg = call("observer.proc.fds", {"pid": -1})
        expect(not r_neg["ok"] and
               r_neg.get("error", {}).get("code") == -32602,
               f"negative pid: {r_neg}")

        r_zero = call("observer.proc.maps", {"pid": 0})
        expect(not r_zero["ok"] and
               r_zero.get("error", {}).get("code") == -32602,
               f"zero pid: {r_zero}")

        # Note: observer.proc.status with non-int pid → -32602.
        r_str = call("observer.proc.status", {"pid": "not-a-number"})
        expect(not r_str["ok"] and
               r_str.get("error", {}).get("code") == -32602,
               f"string pid: {r_str}")

        # net.sockets accepts no-arg call; if /proc is missing we'll see
        # -32000 from the transport layer, but we only run live below.

        # --- live local cases ------------------------------------------
        if not os.path.exists("/proc/self/status"):
            print("observer smoke test PASSED (live cases SKIPPED — no /proc)")
            return

        # The daemon process is `ldbd`; query its own pid for proc.*.
        ldbd_pid = proc.pid

        r_fds = call("observer.proc.fds", {"pid": ldbd_pid})
        expect(r_fds["ok"], f"observer.proc.fds: {r_fds}")
        if r_fds["ok"]:
            d = r_fds["data"]
            expect("fds" in d and "total" in d, f"shape: {d}")
            expect(d["total"] == len(d["fds"]),
                   f"total/len mismatch: total={d['total']} len={len(d['fds'])}")
            expect(d["total"] >= 3, f"expected >= 3 fds: {d['total']}")
            for e in d["fds"]:
                expect(set(e.keys()) >= {"fd", "target", "type"},
                       f"fd entry shape: {e}")

        r_maps = call("observer.proc.maps", {"pid": ldbd_pid})
        expect(r_maps["ok"], f"observer.proc.maps: {r_maps}")
        if r_maps["ok"]:
            d = r_maps["data"]
            expect("regions" in d and "total" in d, f"maps shape: {d}")
            expect(d["total"] > 5, f"expected > 5 regions: {d['total']}")
            for reg in d["regions"][:5]:
                expect(set(reg.keys()) >= {"start", "end", "perm",
                                           "offset", "dev", "inode"},
                       f"region shape: {reg}")

        # view: limit + offset on a paged endpoint.
        r_paged = call("observer.proc.maps",
                       {"pid": ldbd_pid, "view": {"limit": 2, "offset": 0}})
        expect(r_paged["ok"], f"observer.proc.maps view: {r_paged}")
        if r_paged["ok"]:
            d = r_paged["data"]
            expect(len(d["regions"]) == 2,
                   f"limit not applied: {len(d['regions'])}")
            expect(d.get("next_offset") == 2,
                   f"next_offset: {d.get('next_offset')}")

        r_status = call("observer.proc.status", {"pid": ldbd_pid})
        expect(r_status["ok"], f"observer.proc.status: {r_status}")
        if r_status["ok"]:
            d = r_status["data"]
            expect("name" in d and "pid" in d and "state" in d,
                   f"status shape: {d}")
            expect(d["pid"] == ldbd_pid,
                   f"reported pid {d['pid']} != ldbd {ldbd_pid}")
            expect(d["name"] == "ldbd",
                   f"name: {d['name']}")

        # Bogus pid (very unlikely to exist) → backend error -32000.
        r_bogus = call("observer.proc.status", {"pid": 2147483647})
        expect(not r_bogus["ok"] and
               r_bogus.get("error", {}).get("code") == -32000,
               f"bogus pid: {r_bogus}")

        r_sock = call("observer.net.sockets", {})
        # On a stripped container without `ss`, this could fail with
        # -32000. Not a hard failure for the smoke test if so — just log.
        if r_sock["ok"]:
            d = r_sock["data"]
            expect("sockets" in d and "total" in d, f"sockets shape: {d}")
            for s in d["sockets"][:5]:
                expect(set(s.keys()) >= {"proto", "state", "local", "peer"},
                       f"socket entry shape: {s}")

            # Filter test: ask for tcp.
            r_tcp = call("observer.net.sockets", {"filter": "tcp"})
            if r_tcp["ok"]:
                for s in r_tcp["data"]["sockets"]:
                    expect(s["proto"] == "tcp",
                           f"non-tcp in tcp filter: {s}")
        else:
            sys.stderr.write(
                f"NOTE: observer.net.sockets failed (perhaps no `ss`): {r_sock}\n")
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
    print("observer smoke test PASSED")


if __name__ == "__main__":
    main()
