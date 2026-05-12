#!/usr/bin/env python3
"""Smoke test for ProbeOrchestrator routing of kind=agent probes
(post-V1 plan #12 phase-3).

End-to-end: ldb client -> ldbd -> orchestrator -> AgentEngine
(persistent across calls) -> ldb-probe-agent subprocess.

Two flavors of acceptance:

  • If the host has the full BPF toolchain (clang + bpftool + CAP_BPF
    + BTF), the agent's attach_uprobe returns a fresh attach_id and
    probe.events drains zero or more events. This requires a
    privileged runner; on this dev box (no clang+bpftool) the agent
    answers `not_supported` and the daemon returns -32000.

  • Either way, the wire round-trip from dispatcher → orchestrator →
    AgentEngine → agent is exercised: a probe.create with kind=agent
    either succeeds OR returns a typed -32000 whose error message
    mentions a known agent-side code (not_supported, no_capability,
    no_btf). Anything else is a regression.

SKIPs when ldb-probe-agent wasn't built (no libbpf at cmake time).
"""
import json
import os
import select
import subprocess
import sys
import tempfile


KNOWN_AGENT_CODES = ("not_supported", "no_capability", "no_btf")


def usage():
    sys.stderr.write(
        "usage: test_probe_agent_route.py <ldbd> <ldb-probe-agent>\n")
    sys.exit(2)


def main():
    if len(sys.argv) != 3:
        usage()
    ldbd, agent = sys.argv[1], sys.argv[2]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n"); sys.exit(1)
    if not os.path.isfile(agent) or not os.access(agent, os.X_OK):
        print(f"SKIP: ldb-probe-agent not built ({agent})")
        return

    store_root = tempfile.mkdtemp(prefix="ldb_smoke_agent_route_")
    try:
        env = dict(os.environ)
        env["LDB_STORE_ROOT"]  = store_root
        env["LDB_PROBE_AGENT"] = agent
        env.setdefault("LLDB_LOG_LEVEL", "error")
        daemon = subprocess.Popen(
            [ldbd, "--stdio", "--log-level", "error"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env, text=True, bufsize=1,
        )

        next_id = [0]
        def call(method, params=None, timeout=15):
            next_id[0] += 1
            rid = f"r{next_id[0]}"
            req = {"jsonrpc": "2.0", "id": rid, "method": method,
                   "params": params or {}}
            daemon.stdin.write(json.dumps(req) + "\n")
            daemon.stdin.flush()
            ready, _, _ = select.select([daemon.stdout], [], [], timeout)
            if not ready:
                try: daemon.kill()
                except Exception: pass
                sys.stderr.write(
                    f"daemon hung on {method} after {timeout}s\n")
                sys.exit(1)
            line = daemon.stdout.readline()
            if not line:
                err = daemon.stderr.read() or ""
                sys.stderr.write(
                    f"daemon closed stdout (stderr was: {err})\n")
                sys.exit(1)
            return json.loads(line)

        failures = []
        def expect(cond, msg):
            if not cond:
                failures.append(msg)

        try:
            # ---- describe.endpoints — kind enum should advertise agent ----
            r = call("describe.endpoints")
            assert r["ok"], r
            for e in r["data"]["endpoints"]:
                if e["method"] == "probe.create":
                    kinds = []
                    try:
                        kinds = e["params_schema"]["properties"]["kind"]["enum"]
                    except (KeyError, TypeError):
                        pass
                    expect("agent" in kinds,
                           f"probe.create.kind enum should include "
                           f"'agent': got {kinds}")
                    break

            # ---- probe.create kind=agent — uprobe form ----
            r = call("probe.create", {
                "kind": "agent",
                "where": {"uprobe": "/bin/sleep:nanosleep"},
                # capture.args[0] selects the embedded program; "" or
                # absent → default ("syscall_count").
                "capture": {"args": [""]},
            })
            if r["ok"]:
                # Live path: host has CAP_BPF + BTF + a clang/bpftool-
                # produced skeleton. probe.create returned a probe_id.
                pid = r["data"].get("probe_id")
                expect(isinstance(pid, str) and pid.startswith("p"),
                       f"probe_id should be 'p<n>' string: {r['data']}")
                # probe.events: any drain (likely zero events) should succeed.
                e = call("probe.events", {"probe_id": pid, "max": 8})
                expect(e["ok"], f"probe.events: {e}")
                expect(isinstance(e["data"].get("events"), list),
                       f"events should be list: {e['data']}")
                # probe.delete: detach + drop.
                d = call("probe.delete", {"probe_id": pid})
                expect(d["ok"], f"probe.delete: {d}")
            else:
                # Toolchain-less path: agent answered with a known code.
                # The dispatcher wraps it as -32000 backend error.
                err = r.get("error", {})
                expect(err.get("code") == -32000,
                       f"agent error should map to -32000: {r}")
                msg = (err.get("message") or "").lower()
                expect(any(c in msg for c in KNOWN_AGENT_CODES),
                       f"error should mention a known agent code "
                       f"{KNOWN_AGENT_CODES}: {msg!r}")

            # ---- probe.create kind=agent — kprobe form, same expectation ----
            r = call("probe.create", {
                "kind": "agent",
                "where": {"kprobe": "do_sys_open"},
            })
            if r["ok"]:
                pid = r["data"]["probe_id"]
                d = call("probe.delete", {"probe_id": pid})
                expect(d["ok"], f"kprobe delete: {d}")
            else:
                err = r.get("error", {})
                expect(err.get("code") == -32000,
                       f"kprobe agent error: {r}")
                msg = (err.get("message") or "").lower()
                expect(any(c in msg for c in KNOWN_AGENT_CODES),
                       f"kprobe error code: {msg!r}")

            # ---- where must set exactly one of {uprobe, kprobe, tracepoint} ----
            r = call("probe.create", {"kind": "agent", "where": {}})
            expect(not r["ok"]
                   and r.get("error", {}).get("code") == -32602,
                   f"empty where should be -32602: {r}")

            # ---- malformed uprobe target (missing colon) — agent path
            #      validates at AgentEngine::attach_uprobe ----
            r = call("probe.create", {
                "kind": "agent",
                "where": {"uprobe": "no_colon_here"},
            })
            expect(not r["ok"],
                   f"malformed uprobe should fail: {r}")
        finally:
            try:
                daemon.stdin.close()
            except Exception:
                pass
            daemon.wait(timeout=5)

        if failures:
            sys.stderr.write("FAILURES:\n")
            for f in failures:
                sys.stderr.write(f"  - {f}\n")
            sys.exit(1)
        print("OK: probe.create kind=agent smoke")
    finally:
        import shutil
        shutil.rmtree(store_root, ignore_errors=True)


if __name__ == "__main__":
    main()
