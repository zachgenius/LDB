#!/usr/bin/env python3
"""Smoke test for target.connect_remote_ssh (M4 part 2).

End-to-end remote debugging over an SSH-tunneled lldb-server. The test
binary lives on this same host; "remote" is reached via passwordless
ssh-to-localhost. SKIPS cleanly when:
  - no passwordless ssh-to-localhost is configured, or
  - lldb-server is not discoverable.

Negative path is always exercised at the dispatcher level:
  - missing inferior_path  → -32602 (kInvalidParams)
  - bogus host             → -32000 (kBackendError)

Positive path (live):
  - target.create_empty
  - target.connect_remote_ssh against the sleeper fixture, expect
    state in {stopped, running}, pid > 0, local_tunnel_port > 0
  - process.detach
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import time


def usage():
    sys.stderr.write(
        "usage: test_connect_remote_ssh.py <ldbd> <sleeper>\n")
    sys.exit(2)


def find_lldb_server():
    env = os.environ.get("LDB_LLDB_SERVER", "")
    if env and os.access(env, os.X_OK):
        return env
    root = os.environ.get("LDB_LLDB_ROOT", "")
    if root:
        cand = os.path.join(root, "bin", "lldb-server")
        if os.access(cand, os.X_OK):
            return cand
    for cand in ("/opt/llvm-22/bin/lldb-server",
                 "/opt/homebrew/opt/llvm/bin/lldb-server",
                 "/usr/local/opt/llvm/bin/lldb-server"):
        if os.access(cand, os.X_OK):
            return cand
    on_path = shutil.which("lldb-server")
    return on_path or ""


def local_sshd_available():
    """Cheap probe: passwordless ssh-to-localhost exits 0?"""
    try:
        r = subprocess.run(
            ["ssh", "-o", "BatchMode=yes",
             "-o", "ConnectTimeout=2",
             "-o", "StrictHostKeyChecking=accept-new",
             "localhost", "/bin/true"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False


def main():
    if len(sys.argv) != 3:
        usage()
    ldbd, sleeper = sys.argv[1], sys.argv[2]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n"); sys.exit(1)
    if not os.path.isfile(sleeper):
        sys.stderr.write(f"sleeper missing: {sleeper}\n"); sys.exit(1)

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
            sys.stderr.write(
                f"daemon closed stdout (stderr was: {stderr})\n")
            sys.exit(1)
        return json.loads(line)

    failures = []
    def expect(cond, msg):
        if not cond: failures.append(msg)

    try:
        # Endpoint should be advertised in describe.endpoints.
        de = call("describe.endpoints", {})
        expect(de["ok"], f"describe.endpoints: {de}")
        names = [e["method"] for e in de["data"]["endpoints"]]
        expect("target.connect_remote_ssh" in names,
               f"target.connect_remote_ssh missing from describe.endpoints: "
               f"{names[-5:]}")

        # Negative: missing inferior_path.
        r1 = call("target.create_empty", {})
        expect(r1["ok"], f"create_empty: {r1}")
        tid = r1["data"]["target_id"]

        r2 = call("target.connect_remote_ssh",
                  {"target_id": tid, "host": "localhost"})
        expect(not r2["ok"] and r2.get("error", {}).get("code") == -32602,
               f"missing inferior_path expected -32602, got {r2}")

        # Negative: bogus host (with a tight ConnectTimeout to keep test fast).
        r3 = call("target.connect_remote_ssh",
                  {"target_id": tid,
                   "host": "nosuchhost.invalid",
                   "ssh_options": ["-o", "ConnectTimeout=1"],
                   "inferior_path": "/bin/true"})
        expect(not r3["ok"] and r3.get("error", {}).get("code") == -32000,
               f"bogus host expected -32000, got {r3}")

        # Positive path — gated.
        if not local_sshd_available():
            print("connect_remote_ssh smoke: passwordless ssh-to-localhost "
                  "not configured; positive path skipped")
        else:
            server = find_lldb_server()
            if not server:
                print("connect_remote_ssh smoke: lldb-server not found; "
                      "positive path skipped")
            else:
                r4 = call("target.create_empty", {})
                expect(r4["ok"], f"create_empty(2): {r4}")
                tid2 = r4["data"]["target_id"]

                r5 = call("target.connect_remote_ssh",
                          {"target_id": tid2,
                           "host": "localhost",
                           "remote_lldb_server": server,
                           "inferior_path": sleeper,
                           "setup_timeout_ms": 15000})
                expect(r5["ok"], f"connect_remote_ssh: {r5}")
                if r5["ok"]:
                    d = r5["data"]
                    expect(d["state"] in ("stopped", "running"),
                           f"unexpected state: {d}")
                    expect(d["pid"] > 0, f"pid not > 0: {d}")
                    expect(d["local_tunnel_port"] > 0,
                           f"local_tunnel_port not > 0: {d}")

                    # Detach to release the remote inferior.
                    r6 = call("process.detach", {"target_id": tid2})
                    expect(r6["ok"], f"detach: {r6}")

                    # Close the target — this should drop the SSH tunnel.
                    r7 = call("target.close", {"target_id": tid2})
                    expect(r7["ok"], f"close: {r7}")
                    print("connect_remote_ssh smoke: positive path "
                          f"exercised against {server}")
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        try:
            proc.wait(timeout=15)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    if failures:
        for f in failures:
            sys.stderr.write(f"FAIL: {f}\n")
        sys.exit(1)
    print("connect_remote_ssh smoke test PASSED")


if __name__ == "__main__":
    main()
