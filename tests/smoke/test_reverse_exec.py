#!/usr/bin/env python3
"""Smoke test for reverse-execution endpoints.

Covers:

  * Schema: process.reverse_continue / process.reverse_step /
    thread.reverse_step appear in describe.endpoints.
  * Negative: reverse_continue on an empty target → -32000 backend
    error. reverse_step with kind="in" / "over" → -32602 invalid params.
  * Live (gated on rr): rr record /bin/true → rr:// connect →
    process.reverse_continue. SKIPs when rr is missing or rr record
    fails (perf_event_paranoid, ptrace_scope, unsupported CPU).
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile


def usage():
    sys.stderr.write("usage: test_reverse_exec.py <ldbd>\n")
    sys.exit(2)


def find_rr():
    return shutil.which("rr") or os.environ.get("LDB_RR_BIN", "")


def main():
    if len(sys.argv) != 2:
        usage()
    ldbd = sys.argv[1]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n")
        sys.exit(1)

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
            sys.stderr.write(f"daemon closed stdout (stderr: {stderr})\n")
            sys.exit(1)
        return json.loads(line)

    failures = []

    def expect(cond, msg):
        if not cond:
            failures.append(msg)

    try:
        # Schema: all three reverse endpoints must be registered.
        r0 = call("describe.endpoints", {})
        expect(r0["ok"], f"describe.endpoints: {r0}")
        methods = {e["method"] for e in r0["data"]["endpoints"]}
        for m in ("process.reverse_continue", "process.reverse_step",
                  "thread.reverse_step"):
            expect(m in methods, f"missing endpoint: {m}")

        # Negative: reverse_continue on a fresh empty target → bad-state
        # backend error (no live process to reverse). The dispatcher
        # maps "no process" to -32002 specifically; raw -32000 is also
        # accepted in case future backend wording changes the mapping.
        r1 = call("target.create_empty", {})
        expect(r1["ok"], f"create_empty: {r1}")
        tid = r1["data"]["target_id"]
        r2 = call("process.reverse_continue", {"target_id": tid})
        code = r2.get("error", {}).get("code")
        expect(not r2["ok"] and code in (-32000, -32002),
               f"reverse_continue on empty target expected -32000/-32002, "
               f"got {r2}")

        # Negative: missing target_id → -32602.
        r3 = call("process.reverse_continue", {})
        expect(not r3["ok"] and r3.get("error", {}).get("code") == -32602,
               f"missing target_id expected -32602, got {r3}")

        # v1.3 carve-out: kind=in/over/out are now accepted at the wire
        # layer. On an empty target the backend rejects with a "no
        # process" / "not stopped" error (-32002 or -32000), NOT the
        # old kind-deferred -32602.
        for k in ("in", "over", "out", "insn"):
            r = call("process.reverse_step",
                     {"target_id": tid, "tid": 1, "kind": k})
            expect(not r["ok"],
                   f"reverse_step kind={k} on empty target should fail: {r}")
            code = r.get("error", {}).get("code")
            expect(code in (-32000, -32002, -32003),
                   f"reverse_step kind={k} expected backend error, got {r}")

        # Unknown kind still -32602.
        r_bad = call("process.reverse_step",
                     {"target_id": tid, "tid": 1, "kind": "sideways"})
        expect(not r_bad["ok"] and
               r_bad.get("error", {}).get("code") == -32602,
               f"unknown kind expected -32602, got {r_bad}")

        # Live positive: gated on rr availability.
        rr_bin = find_rr()
        if not rr_bin:
            print("reverse_exec smoke: rr not installed; negative path "
                  "verified, live path skipped")
        else:
            with tempfile.TemporaryDirectory(prefix="ldb-rev-smoke-") as troot:
                trace_dir = os.path.join(troot, "true-0")
                rec_env = dict(env)
                rec_env["_RR_TRACE_DIR"] = troot
                rec = subprocess.run(
                    [rr_bin, "record", "-o", trace_dir, "/bin/true"],
                    env=rec_env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    timeout=30,
                )
                if rec.returncode != 0:
                    err = rec.stderr.decode("utf-8", errors="replace").strip()
                    print(f"reverse_exec smoke: rr record failed "
                          f"(rc={rec.returncode}, stderr: {err}); "
                          "negative path verified, live path skipped")
                else:
                    r4 = call("target.create_empty", {})
                    expect(r4["ok"], f"create_empty (live): {r4}")
                    tlive = r4["data"]["target_id"]

                    r5 = call("target.connect_remote",
                              {"target_id": tlive,
                               "url": f"rr://{trace_dir}"})
                    expect(r5["ok"], f"rr:// connect_remote: {r5}")
                    if r5["ok"]:
                        r6 = call("process.reverse_continue",
                                  {"target_id": tlive})
                        # Either it succeeds (state in stopped/exited/running)
                        # or, if rr replay is already at the beginning of the
                        # trace, it surfaces a clear backend error. Both are
                        # acceptable — the failure we *don't* want is a
                        # schema-shaped surprise.
                        if r6["ok"]:
                            st = r6["data"].get("state", "")
                            expect(st in ("stopped", "running", "exited"),
                                   f"unexpected state: {r6['data']}")
                        else:
                            code = r6.get("error", {}).get("code")
                            expect(code in (-32000, -32002, -32003),
                                   f"unexpected error code: {r6}")

                    r7 = call("target.close", {"target_id": tlive})
                    expect(r7["ok"], f"target.close: {r7}")
                    print(f"reverse_exec smoke: live rr round trip OK "
                          f"against {rr_bin}")
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
    print("reverse_exec smoke test PASSED")


if __name__ == "__main__":
    main()
