#!/usr/bin/env python3
"""Smoke test for value.eval.

Launches the structs fixture stop-at-entry, discovers a tid via
thread.list, then exercises value.eval over the wire:

  * a simple integer expression returns ok=true with a value carrying
    a summary that mentions "3" (1+2).
  * a malformed expression returns ok=true with {error: '...'} as
    DATA — not a transport-level error. The agent branches on
    `data.error` being present.
  * a hostile (infinite-loop) expression bounded by a small timeout
    returns ok=true with {error: '...'} promptly (well under the
    smoke-test timeout).
  * missing `expr` → -32602.
  * bogus tid → -32000.
"""
import json
import os
import subprocess
import sys
import time


def usage():
    sys.stderr.write("usage: test_value_eval.py <ldbd> <fixture>\n")
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

    try:
        r1 = call("target.open", {"path": fixture})
        expect(r1["ok"], f"target.open: {r1}")

        r2 = call("process.launch",
                  {"target_id": 1, "stop_at_entry": True})
        expect(r2["ok"], f"process.launch: {r2}")
        expect(r2["data"]["state"] == "stopped",
               f"expected stopped, got {r2['data']['state']}")

        r3 = call("thread.list", {"target_id": 1})
        expect(r3["ok"], f"thread.list: {r3}")
        threads = r3["data"]["threads"]
        if not threads:
            raise SystemExit(1)
        tid = threads[0]["tid"]

        # Successful integer eval.
        r4 = call("value.eval",
                  {"target_id": 1, "tid": tid, "expr": "1 + 2"})
        expect(r4["ok"], f"value.eval (1+2): {r4}")
        expect("value" in r4["data"],
               f"missing 'value' on success: {r4['data']}")
        expect("error" not in r4["data"],
               f"unexpected 'error' on success: {r4['data']}")
        v = r4["data"].get("value", {})
        # The summary should mention "3".
        expect("summary" in v and "3" in v["summary"],
               f"expected summary containing 3, got {v}")

        # Syntax error → ok=true with error as data.
        r5 = call("value.eval",
                  {"target_id": 1, "tid": tid,
                   "expr": "this is not++ a valid expr %%"})
        expect(r5["ok"],
               f"value.eval bad expr should be data, got transport err {r5}")
        expect("error" in r5["data"] and r5["data"]["error"],
               f"expected error data, got {r5['data']}")
        expect("value" not in r5["data"],
               f"unexpected 'value' on eval failure: {r5['data']}")

        # Infinite loop bounded by 100ms timeout: must return promptly.
        t0 = time.monotonic()
        r6 = call("value.eval",
                  {"target_id": 1, "tid": tid,
                   "expr": "({ int i = 0; while (1) { i++; } i; })",
                   "timeout_us": 100_000})
        elapsed = time.monotonic() - t0
        expect(r6["ok"], f"timeout eval should be ok=true, got {r6}")
        expect("error" in r6["data"] and r6["data"]["error"],
               f"expected error on timeout, got {r6['data']}")
        # Generous bound: 5s. Real timeout is 100ms; LLDB has some
        # JIT-shutdown overhead.
        expect(elapsed < 5.0,
               f"hostile expr did not return promptly: {elapsed:.2f}s")

        # Missing expr → -32602.
        r7 = call("value.eval", {"target_id": 1, "tid": tid})
        expect(not r7["ok"] and r7.get("error", {}).get("code") == -32602,
               f"missing expr expected -32602, got {r7}")

        # Bogus tid → -32000.
        r8 = call("value.eval",
                  {"target_id": 1, "tid": 0xDEAD_BEEF, "expr": "1+1"})
        expect(not r8["ok"] and r8.get("error", {}).get("code") == -32000,
               f"bogus tid expected -32000, got {r8}")

        # Bogus target_id → -32000.
        r9 = call("value.eval",
                  {"target_id": 9999, "tid": tid, "expr": "1+1"})
        expect(not r9["ok"] and r9.get("error", {}).get("code") == -32000,
               f"bogus target_id expected -32000, got {r9}")

        # Cleanup.
        call("process.kill", {"target_id": 1})
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
    print("value.eval smoke test PASSED")


if __name__ == "__main__":
    main()
