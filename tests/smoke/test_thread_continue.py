#!/usr/bin/env python3
"""Smoke test for thread.continue and process.continue+tid (Tier 4 §14).

Pins the v0.3 protocol surface for non-stop debugging:
  * thread.continue({target_id, tid}) resumes the inferior with sync
    semantics (whole-process resume; passthrough into continue_process).
  * process.continue accepts an optional `tid` and routes the same way.

The runtime gap is documented in docs/11-non-stop.md: per-thread
keep-running while siblings stay stopped lands in v0.4 with
SBProcess::SetAsync(true) — the wire shape is shipped now so client
code is async-ready.

Asserts:
  * thread.continue is a registered endpoint advertised by
    describe.endpoints.
  * thread.continue from stop-at-entry returns a valid process state.
  * process.continue+tid resumes the process (sync semantics — agents
    SHOULD treat thread.continue as equivalent to process.continue
    under v0.3 protocol).
  * Missing `tid` on thread.continue → -32602.
  * Bogus target_id → -32000.
"""
import json
import os
import subprocess
import sys


def usage():
    sys.stderr.write("usage: test_thread_continue.py <ldbd> <fixture>\n")
    sys.exit(2)


def main():
    if len(sys.argv) != 3:
        usage()
    ldbd, fixture = sys.argv[1], sys.argv[2]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n"); sys.exit(1)
    if not os.path.isfile(fixture):
        sys.stderr.write(f"fixture missing: {fixture}\n"); sys.exit(1)

    env = dict(os.environ)
    env.setdefault("LLDB_LOG_LEVEL", "error")

    proc = subprocess.Popen(
        [ldbd, "--stdio", "--log-level", "error"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
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
            sys.stderr.write(f"daemon closed stdout (stderr was: {stderr})\n")
            sys.exit(1)
        return json.loads(line)

    failures = []
    def expect(cond, msg):
        if not cond:
            failures.append(msg)

    valid_terminal_states = {"exited", "crashed", "stopped", "running",
                             "detached", "invalid", "none"}

    try:
        # 1) describe.endpoints advertises thread.continue and the
        #    optional `tid` on process.continue.
        rd = call("describe.endpoints")
        expect(rd["ok"], f"describe.endpoints: {rd}")
        eps = {e["method"]: e for e in rd["data"]["endpoints"]}
        expect("thread.continue" in eps,
               "thread.continue must be in describe.endpoints catalog")
        if "thread.continue" in eps:
            tc_summary = eps["thread.continue"].get("summary", "")
            expect("v0.3" in tc_summary or "sync" in tc_summary.lower(),
                   "thread.continue summary must surface v0.3-sync semantics")
            tc_required = eps["thread.continue"]["params_schema"].get(
                "required", [])
            expect("target_id" in tc_required and "tid" in tc_required,
                   f"thread.continue params must require target_id and tid; "
                   f"got required={tc_required}")
        if "process.continue" in eps:
            pc_props = eps["process.continue"]["params_schema"].get(
                "properties", {})
            expect("tid" in pc_props,
                   "process.continue must advertise optional `tid` "
                   "in its params_schema (Tier 4 §14)")

        # 2) Open + launch the fixture, observe a stopped thread.
        r1 = call("target.open", {"path": fixture})
        expect(r1["ok"], f"target.open: {r1}")
        target_id = r1["data"]["target_id"]

        r2 = call("process.launch",
                  {"target_id": target_id, "stop_at_entry": True})
        expect(r2["ok"], f"process.launch: {r2}")
        expect(r2["data"]["state"] == "stopped",
               f"expected state=stopped, got {r2['data']}")

        r3 = call("thread.list", {"target_id": target_id})
        expect(r3["ok"], f"thread.list: {r3}")
        threads = r3["data"]["threads"]
        expect(len(threads) >= 1, f"expected >=1 thread, got {threads}")
        if not threads:
            raise SystemExit(1)
        tid = threads[0]["tid"]
        # v0.3: each thread's `state` is the whole-process state replicated
        # per-thread. Pin the contract so future async work doesn't
        # silently regress this field on the read path.
        expect(threads[0]["state"] in valid_terminal_states,
               f"thread.state must be one of {valid_terminal_states}, "
               f"got {threads[0]['state']}")

        # 3) thread.continue resumes the inferior. Sync passthrough →
        #    structs returns from main almost immediately, expect kExited.
        rc = call("thread.continue",
                  {"target_id": target_id, "tid": tid})
        expect(rc["ok"], f"thread.continue: {rc}")
        expect(rc["data"]["state"] in valid_terminal_states,
               f"thread.continue: unexpected state {rc['data']}")
        # v0.3 sync semantics: structs's main exits quickly, so by the
        # time thread.continue returns the process should be exited.
        # Document this for agents reading the test.
        expect(rc["data"]["state"] == "exited",
               f"thread.continue (v0.3 sync): expected exited, got "
               f"{rc['data']}")

        # 4) Re-launch and exercise process.continue+tid (same path).
        r4 = call("process.launch",
                  {"target_id": target_id, "stop_at_entry": True})
        expect(r4["ok"], f"relaunch: {r4}")
        r5 = call("thread.list", {"target_id": target_id})
        expect(r5["ok"], f"thread.list#2: {r5}")
        threads2 = r5["data"]["threads"]
        if not threads2:
            raise SystemExit(1)
        tid2 = threads2[0]["tid"]

        rpc = call("process.continue",
                   {"target_id": target_id, "tid": tid2})
        expect(rpc["ok"], f"process.continue+tid: {rpc}")
        expect(rpc["data"]["state"] == "exited",
               f"process.continue+tid (v0.3 sync): expected exited, got "
               f"{rpc['data']}")

        # 5) Error paths.
        r4 = call("process.launch",
                  {"target_id": target_id, "stop_at_entry": True})
        expect(r4["ok"], f"relaunch#2: {r4}")
        r5 = call("thread.list", {"target_id": target_id})
        threads3 = r5["data"]["threads"]
        if not threads3:
            raise SystemExit(1)
        tid3 = threads3[0]["tid"]

        # Missing tid on thread.continue → -32602.
        re1 = call("thread.continue", {"target_id": target_id})
        expect(not re1["ok"] and
               re1.get("error", {}).get("code") == -32602,
               f"thread.continue missing tid: expected -32602, got {re1}")

        # Missing target_id on thread.continue → -32602.
        re2 = call("thread.continue", {"tid": tid3})
        expect(not re2["ok"] and
               re2.get("error", {}).get("code") == -32602,
               f"thread.continue missing target_id: expected -32602, got {re2}")

        # Bogus target_id surfaces backend error (-32000).
        re3 = call("thread.continue",
                   {"target_id": 9999, "tid": tid3})
        expect(not re3["ok"] and
               re3.get("error", {}).get("code") == -32000,
               f"thread.continue bogus target_id: expected -32000, got {re3}")

        # Cleanup.
        call("process.kill", {"target_id": target_id})
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
    print("thread.continue smoke test PASSED")


if __name__ == "__main__":
    main()
