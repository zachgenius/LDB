#!/usr/bin/env python3
"""Smoke test for mem.read / mem.read_cstr / mem.regions / mem.search.

Spawns the sleeper fixture (so all relocations are complete), attaches
ldbd to it, then exercises each memory primitive.
"""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _ptrace_probe import maybe_skip_ptrace


def usage():
    sys.stderr.write("usage: test_memory.py <ldbd> <sleeper>\n")
    sys.exit(2)


def main():
    if len(sys.argv) != 3:
        usage()
    ldbd, sleeper = sys.argv[1], sys.argv[2]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n"); sys.exit(1)
    if not os.path.isfile(sleeper):
        sys.stderr.write(f"sleeper missing: {sleeper}\n"); sys.exit(1)
    maybe_skip_ptrace(ldbd, "smoke_memory")

    inferior = subprocess.Popen(
        [sleeper], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        line = inferior.stdout.readline()
        if "READY=" not in line:
            sys.stderr.write(f"sleeper didn't print READY: {line}\n")
            sys.exit(1)
        pid_token = line.split()[0]
        inferior_pid = int(pid_token[len("PID="):])

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
            if not cond: failures.append(msg)

        try:
            r1 = call("target.create_empty", {})
            expect(r1["ok"], f"target.create_empty: {r1}")
            target_id = r1["data"]["target_id"]

            r2 = call("target.attach",
                      {"target_id": target_id, "pid": inferior_pid})
            expect(r2["ok"], f"target.attach: {r2}")

            # mem.regions — should have at least one executable region.
            r3 = call("mem.regions", {"target_id": target_id})
            expect(r3["ok"], f"mem.regions: {r3}")
            regions = r3["data"]["regions"]
            expect(len(regions) > 0, "expected at least one region")
            expect(any(r.get("x") for r in regions),
                   "expected at least one executable region")

            # Resolve k_marker via symbol.find to get its load_addr.
            r4 = call("symbol.find",
                      {"target_id": target_id, "name": "k_marker"})
            expect(r4["ok"], f"symbol.find: {r4}")
            matches = r4["data"]["matches"]
            expect(len(matches) >= 1, f"k_marker not found: {r4}")
            if not matches:
                raise SystemExit(1)
            ptr_load_addr = matches[0].get("load_addr")
            expect(ptr_load_addr is not None,
                   f"missing load_addr in symbol match: {matches[0]}")

            # mem.read 8 bytes from k_marker (the pointer itself).
            r5 = call("mem.read",
                      {"target_id": target_id,
                       "address": ptr_load_addr, "size": 8})
            expect(r5["ok"], f"mem.read: {r5}")
            hex_str = r5["data"]["bytes"]
            expect(len(hex_str) == 16,
                   f"expected 16 hex chars (8 bytes), got {hex_str}")

            # Decode pointer (little-endian).
            ptr_bytes = bytes.fromhex(hex_str)
            string_addr = int.from_bytes(ptr_bytes, "little")
            expect(string_addr != 0, "pointer value is zero")

            # mem.read_cstr at that address.
            r6 = call("mem.read_cstr",
                      {"target_id": target_id,
                       "address": string_addr, "max_len": 64})
            expect(r6["ok"], f"mem.read_cstr: {r6}")
            expect(r6["data"]["value"] == "LDB_SLEEPER_MARKER_v1",
                   f"unexpected value: {r6['data']}")
            expect(r6["data"]["truncated"] is False,
                   f"unexpected truncated: {r6['data']}")

            # mem.search by text needle.
            r7 = call("mem.search",
                      {"target_id": target_id,
                       "needle": {"text": "LDB_SLEEPER_MARKER_v1"},
                       "max_hits": 8})
            expect(r7["ok"], f"mem.search: {r7}")
            expect(len(r7["data"]["hits"]) >= 1,
                   f"expected hits, got {r7['data']}")

            # mem.search by hex needle (same string in hex).
            hex_needle = "LDB_SLEEPER_MARKER_v1".encode().hex()
            r8 = call("mem.search",
                      {"target_id": target_id, "needle": hex_needle,
                       "max_hits": 4})
            expect(r8["ok"], f"mem.search hex: {r8}")
            expect(len(r8["data"]["hits"]) >= 1,
                   f"hex needle no hits: {r8['data']}")

            # mem.read oversize → -32000 backend error.
            r9 = call("mem.read",
                      {"target_id": target_id, "address": 0,
                       "size": 2 * 1024 * 1024})
            expect(not r9["ok"] and r9.get("error", {}).get("code") == -32000,
                   f"oversize mem.read should error: {r9}")

            # mem.search invalid needle (odd-length hex).
            r10 = call("mem.search",
                       {"target_id": target_id, "needle": "abc"})
            expect(not r10["ok"] and r10.get("error", {}).get("code") == -32602,
                   f"odd hex should be -32602: {r10}")

            # mem.regions with view.fields projection.
            r11 = call("mem.regions",
                       {"target_id": target_id,
                        "view": {"fields": ["base", "size"], "limit": 3}})
            expect(r11["ok"], f"mem.regions w/ view: {r11}")
            expect(len(r11["data"]["regions"]) <= 3,
                   f"view.limit ignored: {r11['data']}")
            for r in r11["data"]["regions"]:
                expect(set(r.keys()) <= {"base", "size"},
                       f"view.fields didn't project: {r}")

            # Cleanup.
            call("process.detach", {"target_id": target_id})
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
        print("memory smoke test PASSED")
    finally:
        try:
            inferior.kill()
        except Exception:
            pass
        try:
            inferior.wait(timeout=5)
        except Exception:
            pass


if __name__ == "__main__":
    main()
