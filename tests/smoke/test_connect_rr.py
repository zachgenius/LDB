#!/usr/bin/env python3
"""Smoke test for target.connect_remote with rr:// URL scheme.

Tier 4 §13. Two cases:

1. Negative — bogus trace path: drives a syntactically-valid rr:// URL
   pointing at a non-existent trace directory. Expects a typed -32000
   backend error within a bounded wall-clock window. This case runs
   ONLY when rr is on PATH (otherwise the parser-or-binary-discovery
   error path is exercised separately by the unit tests).

2. Live — rr record + replay round trip: gated on `which rr`. SKIPs
   cleanly when rr is not installed, OR when `rr record /bin/true`
   fails (typically due to ptrace_scope / kernel.perf_event_paranoid /
   container constraints — none of which are LDB's bug).
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time


def usage():
    sys.stderr.write("usage: test_connect_rr.py <ldbd>\n")
    sys.exit(2)


def find_rr():
    return shutil.which("rr") or os.environ.get("LDB_RR_BIN", "")


def main():
    if len(sys.argv) != 2:
        usage()
    ldbd = sys.argv[1]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n"); sys.exit(1)

    rr_bin = find_rr()
    if not rr_bin:
        # No rr → no live path. The parser-and-discovery negative paths
        # are covered by the unit suite; here we just SKIP cleanly so
        # the test passes with a logged reason.
        print("connect_rr smoke: rr not installed (apt is unusable on "
              "this Pop!_OS box per project notes; manual deb extraction "
              "is the workaround). SKIPPING — unit tests cover the "
              "parser and discovery error paths.")
        return

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
        if not cond: failures.append(msg)

    try:
        # Negative: bogus rr trace path. rr replay fails to open the
        # trace, the gdb-remote port never opens, and our setup_timeout
        # fires. Daemon must surface -32000 within ~20s.
        r1 = call("target.create_empty", {})
        expect(r1["ok"], f"create_empty: {r1}")
        tid = r1["data"]["target_id"]

        bogus_trace = f"/tmp/ldb-rr-smoke-does-not-exist-{os.getpid()}"
        t0 = time.time()
        r2 = call("target.connect_remote",
                  {"target_id": tid, "url": f"rr://{bogus_trace}"})
        elapsed = time.time() - t0
        expect(not r2["ok"] and r2.get("error", {}).get("code") == -32000,
               f"bogus rr trace expected -32000, got {r2}")
        expect(elapsed < 20.0,
               f"bogus rr trace took {elapsed:.2f}s — should be bounded")

        # Live positive: rr record /bin/true → rr://trace_dir.
        with tempfile.TemporaryDirectory(prefix="ldb-rr-smoke-") as trace_root:
            trace_dir = os.path.join(trace_root, "true-0")
            record_env = dict(env)
            record_env["_RR_TRACE_DIR"] = trace_root
            rec = subprocess.run(
                [rr_bin, "record", "-o", trace_dir, "/bin/true"],
                env=record_env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=30,
            )
            if rec.returncode != 0:
                stderr = rec.stderr.decode("utf-8", errors="replace")
                # ptrace_scope/perf_event constraints — not LDB's bug.
                # SKIP the live path; the negative path was verified above.
                print(f"connect_rr smoke: rr record failed (rc={rec.returncode}, "
                      f"stderr: {stderr.strip()}); negative path verified, "
                      "live path skipped")
            else:
                # Drive the daemon: connect, expect a real state, close.
                r3 = call("target.create_empty", {})
                expect(r3["ok"], f"create_empty (live): {r3}")
                tid_live = r3["data"]["target_id"]

                r4 = call("target.connect_remote",
                          {"target_id": tid_live,
                           "url": f"rr://{trace_dir}"})
                expect(r4["ok"], f"connect_remote rr://: {r4}")
                if r4["ok"]:
                    state = r4["data"].get("state", "")
                    expect(state in ("stopped", "running", "exited"),
                           f"unexpected post-connect state: {r4['data']}")

                # Close: TargetResource dtor SIGTERMs the rr child.
                # `target.close` is on the wire; if the agent worked
                # correctly, the rr replay subprocess is gone after this.
                r5 = call("target.close", {"target_id": tid_live})
                expect(r5["ok"], f"target.close: {r5}")
                print(f"connect_rr smoke: live rr round trip OK against "
                      f"{rr_bin}")
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
    print("connect_rr smoke test PASSED")


if __name__ == "__main__":
    main()
