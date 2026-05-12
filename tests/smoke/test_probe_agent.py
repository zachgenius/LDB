#!/usr/bin/env python3
"""Smoke test for agent.hello (post-V1 #12 phase-2).

End-to-end: ldb client -> ldbd -> spawns ldb-probe-agent -> hello frame
-> reads HelloOk response -> ldbd shuts the agent down -> response
flows back. Validates that the daemon side of the wire works without
needing CAP_BPF or a live BPF program.

SKIPs when ldb-probe-agent is not on disk (host built ldbd without
libbpf, so the agent binary wasn't produced).
"""
import json
import os
import select
import subprocess
import sys
import tempfile


def usage():
    sys.stderr.write("usage: test_probe_agent.py <ldbd> <ldb-probe-agent>\n")
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

    store_root = tempfile.mkdtemp(prefix="ldb_smoke_agent_")
    try:
        env = dict(os.environ)
        env["LDB_STORE_ROOT"]   = store_root
        env["LDB_PROBE_AGENT"]  = agent
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
            # ---- describe.endpoints surfaces agent.hello ----
            r = call("describe.endpoints")
            assert r["ok"], r
            methods = {e["method"] for e in r["data"]["endpoints"]}
            expect("agent.hello" in methods,
                   "agent.hello missing from describe.endpoints")

            # ---- agent.hello round-trip ----
            r = call("agent.hello")
            expect(r["ok"], f"agent.hello: {r}")
            data = r.get("data", {})
            expect(data.get("agent_path") == agent,
                   f"agent_path should echo LDB_PROBE_AGENT: {data}")
            expect(isinstance(data.get("agent_version"), str)
                   and data["agent_version"],
                   f"agent_version should be a non-empty string: {data}")
            expect(isinstance(data.get("libbpf_version"), str)
                   and data["libbpf_version"],
                   f"libbpf_version should be a non-empty string: {data}")
            expect("btf_present" in data,
                   f"btf_present should be present: {data}")
            expect(isinstance(data.get("embedded_programs"), list),
                   f"embedded_programs should be a list: {data}")

            # ---- agent.hello with LDB_PROBE_AGENT unset+missing binary →
            # we can't easily exercise this here because the env is sticky
            # to the daemon's environ at spawn time. The negative path is
            # covered by AgentEngine::discover_agent returning "" and the
            # dispatcher mapping to kBadState — see dispatcher.cpp.
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
        print("OK: agent.hello smoke")
    finally:
        import shutil
        shutil.rmtree(store_root, ignore_errors=True)


if __name__ == "__main__":
    main()
