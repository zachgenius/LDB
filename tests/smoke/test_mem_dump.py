#!/usr/bin/env python3
"""Smoke test for mem.dump_artifact (M3 closeout).

Spawns the sleeper fixture, attaches ldbd to it, dumps a region of
memory via mem.dump_artifact, then verifies the bytes round-trip via
artifact.get and match a parallel mem.read at the same address.
Exercises the negative paths (-32602 / -32002 / -32000) end-to-end.
"""
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile


def usage():
    sys.stderr.write("usage: test_mem_dump.py <ldbd> <sleeper>\n")
    sys.exit(2)


def main():
    if len(sys.argv) != 3:
        usage()
    ldbd, sleeper = sys.argv[1], sys.argv[2]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n"); sys.exit(1)
    if not os.path.isfile(sleeper):
        sys.stderr.write(f"sleeper missing: {sleeper}\n"); sys.exit(1)

    store_root = tempfile.mkdtemp(prefix="ldb_smoke_memdump_")

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
        env["LDB_STORE_ROOT"] = store_root
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
                stderr = proc.stderr.read()
                sys.stderr.write(
                    f"daemon closed stdout (stderr was: {stderr})\n")
                sys.exit(1)
            return json.loads(line)

        failures = []
        def expect(cond, msg):
            if not cond: failures.append(msg)

        try:
            # describe.endpoints must list mem.dump_artifact.
            r0 = call("describe.endpoints")
            expect(r0["ok"], f"describe.endpoints: {r0}")
            methods = {e["method"] for e in r0["data"]["endpoints"]}
            expect("mem.dump_artifact" in methods,
                   f"missing endpoint mem.dump_artifact: {sorted(methods)}")

            # Attach to the sleeper.
            r1 = call("target.create_empty", {})
            expect(r1["ok"], f"target.create_empty: {r1}")
            target_id = r1["data"]["target_id"]

            r2 = call("target.attach",
                      {"target_id": target_id, "pid": inferior_pid})
            expect(r2["ok"], f"target.attach: {r2}")

            # Resolve k_marker (a const char* const). 8 bytes is the
            # pointer itself — easiest dependable region to dump.
            r3 = call("symbol.find",
                      {"target_id": target_id, "name": "k_marker"})
            expect(r3["ok"], f"symbol.find: {r3}")
            matches = r3["data"]["matches"]
            expect(len(matches) >= 1, f"k_marker not found: {r3}")
            if not matches:
                raise SystemExit(1)
            addr = matches[0].get("load_addr")
            expect(addr is not None, f"missing load_addr: {matches[0]}")

            # mem.dump_artifact: read+store in one shot.
            r4 = call("mem.dump_artifact", {
                "target_id": target_id,
                "addr": addr,
                "len": 8,
                "build_id": "build-sleeper",
                "name": "k_marker_ptr.bin",
                "format": "raw",
                "meta": {"capture": "smoke"},
            })
            expect(r4["ok"], f"mem.dump_artifact: {r4}")
            artifact_id = r4["data"]["artifact_id"]
            expect(artifact_id > 0, f"bad artifact_id: {artifact_id}")
            expect(r4["data"]["byte_size"] == 8,
                   f"byte_size: {r4['data']['byte_size']}")
            sha = r4["data"]["sha256"]
            expect(len(sha) == 64 and all(
                       c in "0123456789abcdef" for c in sha),
                   f"sha256 not 64 hex chars: {sha!r}")
            expect(r4["data"]["name"] == "k_marker_ptr.bin",
                   f"name: {r4['data']}")

            # mem.read the same region and verify byte-for-byte equality
            # with the stored artifact.
            r5 = call("mem.read",
                      {"target_id": target_id, "address": addr, "size": 8})
            expect(r5["ok"], f"mem.read: {r5}")
            mem_bytes = bytes.fromhex(r5["data"]["bytes"])
            expect(hashlib.sha256(mem_bytes).hexdigest() == sha,
                   "stored sha doesn't match a fresh mem.read at the same addr")

            r6 = call("artifact.get",
                      {"build_id": "build-sleeper",
                       "name": "k_marker_ptr.bin"})
            expect(r6["ok"], f"artifact.get: {r6}")
            stored = base64.b64decode(r6["data"]["bytes_b64"])
            expect(stored == mem_bytes,
                   f"stored bytes mismatch: {stored.hex()} vs "
                   f"{mem_bytes.hex()}")
            expect(r6["data"]["format"] == "raw",
                   f"format: {r6['data']}")
            expect(r6["data"]["meta"]["capture"] == "smoke",
                   f"meta: {r6['data']}")

            # Re-dump same (build_id, name) → replaces. id should change.
            r7 = call("mem.dump_artifact", {
                "target_id": target_id,
                "addr": addr,
                "len": 8,
                "build_id": "build-sleeper",
                "name": "k_marker_ptr.bin",
            })
            expect(r7["ok"], f"replace dump: {r7}")
            expect(r7["data"]["artifact_id"] != artifact_id,
                   f"replace should change id: {r7['data']}")

            # --- error paths -------------------------------------------
            # Missing required field.
            re1 = call("mem.dump_artifact",
                       {"target_id": target_id, "addr": addr,
                        "build_id": "b", "name": "n"})  # no len
            expect(not re1["ok"] and
                   re1.get("error", {}).get("code") == -32602,
                   f"missing len should be -32602: {re1}")

            # Bad target_id → backend error.
            re2 = call("mem.dump_artifact",
                       {"target_id": 9999, "addr": addr, "len": 8,
                        "build_id": "b", "name": "n"})
            expect(not re2["ok"] and
                   re2.get("error", {}).get("code") == -32000,
                   f"bogus target_id should be -32000: {re2}")

            # Oversize len → backend error.
            re3 = call("mem.dump_artifact",
                       {"target_id": target_id, "addr": addr,
                        "len": 2 * 1024 * 1024,
                        "build_id": "b", "name": "n"})
            expect(not re3["ok"] and
                   re3.get("error", {}).get("code") == -32000,
                   f"oversize len should be -32000: {re3}")

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
        print("mem.dump_artifact smoke test PASSED")
    finally:
        try:
            inferior.kill()
        except Exception:
            pass
        try:
            inferior.wait(timeout=5)
        except Exception:
            pass
        shutil.rmtree(store_root, ignore_errors=True)


if __name__ == "__main__":
    main()
