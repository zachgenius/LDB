#!/usr/bin/env python3
"""Smoke test for value.read.

Launches the structs fixture stop-at-entry, discovers a tid via
thread.list, then exercises value.read over the wire:

  * top-level identifier (`g_origin`) returns ok=true with a value
    whose type mentions point2.
  * dotted-path traversal (`g_origin.x`) returns ok=true with a leaf
    of integer type.
  * indexed-path traversal (`g_arr[2]`) returns ok=true.
  * struct value carries `children` for one-shot inspection.
  * malformed path returns ok=true with `data.error` set.
  * unknown root returns ok=true with `data.error` set.
  * missing `path` → -32602.
  * bogus tid → -32000.
"""
import json
import os
import subprocess
import sys


def usage():
    sys.stderr.write("usage: test_value_read.py <ldbd> <fixture>\n")
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

        # Top-level global.
        r4 = call("value.read",
                  {"target_id": 1, "tid": tid, "path": "g_origin"})
        expect(r4["ok"], f"value.read g_origin: {r4}")
        expect("value" in r4["data"],
               f"missing 'value' on success: {r4['data']}")
        expect("error" not in r4["data"],
               f"unexpected 'error': {r4['data']}")
        v = r4["data"]["value"]
        expect(v["name"] == "g_origin", f"name mismatch: {v}")
        expect("point2" in v["type"], f"type mismatch: {v}")
        # Struct → has children.
        expect("children" in r4["data"] and len(r4["data"]["children"]) >= 2,
               f"expected children for struct value: {r4['data']}")
        child_names = {c["name"] for c in r4["data"]["children"]}
        expect({"x", "y"}.issubset(child_names),
               f"expected x,y children, got {child_names}")

        # Dotted path.
        r5 = call("value.read",
                  {"target_id": 1, "tid": tid, "path": "g_origin.x"})
        expect(r5["ok"], f"value.read g_origin.x: {r5}")
        v5 = r5["data"]["value"]
        expect(v5["name"] == "x", f"leaf name mismatch: {v5}")
        expect("int" in v5["type"], f"leaf type mismatch: {v5}")

        # Nested dotted path.
        r6 = call("value.read",
                  {"target_id": 1, "tid": tid,
                   "path": "g_login_template.magic"})
        expect(r6["ok"], f"value.read magic: {r6}")
        v6 = r6["data"]["value"]
        expect(v6["name"] == "magic", f"name mismatch: {v6}")

        # Indexed path.
        r7 = call("value.read",
                  {"target_id": 1, "tid": tid, "path": "g_arr[2]"})
        expect(r7["ok"], f"value.read g_arr[2]: {r7}")
        v7 = r7["data"]["value"]
        expect("int" in v7["type"], f"array elem type: {v7}")

        # Malformed path → error as data.
        r8 = call("value.read",
                  {"target_id": 1, "tid": tid, "path": "g_origin."})
        expect(r8["ok"],
               f"malformed path should be data, got transport err {r8}")
        expect("error" in r8["data"] and r8["data"]["error"],
               f"expected error on malformed path, got {r8['data']}")
        expect("value" not in r8["data"],
               f"unexpected 'value' on malformed path: {r8['data']}")

        # Unknown root → error as data.
        r9 = call("value.read",
                  {"target_id": 1, "tid": tid,
                   "path": "no_such_global_xyz"})
        expect(r9["ok"], f"unknown root should be data, got {r9}")
        expect("error" in r9["data"] and r9["data"]["error"],
               f"expected error on unknown root, got {r9['data']}")

        # No-such-member → error as data.
        r10 = call("value.read",
                   {"target_id": 1, "tid": tid,
                    "path": "g_origin.nope"})
        expect(r10["ok"], f"no-such-member should be data, got {r10}")
        expect("error" in r10["data"] and "nope" in r10["data"]["error"],
               f"expected nope-bearing error, got {r10['data']}")

        # Missing path → -32602.
        r11 = call("value.read", {"target_id": 1, "tid": tid})
        expect(not r11["ok"] and r11.get("error", {}).get("code") == -32602,
               f"missing path expected -32602, got {r11}")

        # Bogus tid → -32000.
        r12 = call("value.read",
                   {"target_id": 1, "tid": 0xDEAD_BEEF,
                    "path": "g_origin"})
        expect(not r12["ok"] and r12.get("error", {}).get("code") == -32000,
               f"bogus tid expected -32000, got {r12}")

        # Bogus target_id → -32000.
        r13 = call("value.read",
                   {"target_id": 9999, "tid": tid, "path": "g_origin"})
        expect(not r13["ok"] and r13.get("error", {}).get("code") == -32000,
               f"bogus target_id expected -32000, got {r13}")

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
    print("value.read smoke test PASSED")


if __name__ == "__main__":
    main()
