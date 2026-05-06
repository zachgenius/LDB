#!/usr/bin/env python3
"""Smoke test for observer.exec (M4 polish, plan §4.6).

Two passes against the same ldbd binary:

  1. NO LDB_OBSERVER_EXEC_ALLOWLIST set → observer.exec returns -32002.
     describe.endpoints still lists the endpoint.
  2. With LDB_OBSERVER_EXEC_ALLOWLIST pointed at a tmpfile that allows
     /bin/echo, observer.exec runs it and returns stdout/exit_code.
     A disallowed argv (/bin/cat /etc/passwd) returns -32003.

We restart ldbd between passes because the daemon reads the env var at
startup. The test does NOT pollute the global test environment with
LDB_OBSERVER_EXEC_ALLOWLIST — the env var is only set in the subprocess
env dict.
"""
import json
import os
import subprocess
import sys
import tempfile


def usage():
    sys.stderr.write("usage: test_observer_exec.py <ldbd>\n")
    sys.exit(2)


def spawn(ldbd, env):
    return subprocess.Popen(
        [ldbd, "--stdio", "--log-level", "error"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env, text=True, bufsize=1,
    )


def make_caller(proc):
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
    return call


def shutdown(proc):
    try:
        proc.stdin.close()
    except Exception:
        pass
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def main():
    if len(sys.argv) != 2:
        usage()
    ldbd = sys.argv[1]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n")
        sys.exit(1)

    failures = []

    def expect(cond, msg):
        if not cond:
            failures.append(msg)

    # ---- Pass 1: no allowlist → -32002 ----------------------------------
    env1 = dict(os.environ)
    env1.pop("LDB_OBSERVER_EXEC_ALLOWLIST", None)
    env1.setdefault("LLDB_LOG_LEVEL", "error")
    proc1 = spawn(ldbd, env1)
    try:
        call = make_caller(proc1)

        r0 = call("describe.endpoints")
        expect(r0["ok"], f"describe.endpoints ok: {r0}")
        methods = {e["method"] for e in r0["data"]["endpoints"]}
        expect("observer.exec" in methods,
               "observer.exec missing from describe.endpoints")

        r1 = call("observer.exec", {"argv": ["/bin/echo", "hello"]})
        expect(not r1["ok"], f"expected error w/o allowlist: {r1}")
        expect(r1.get("error", {}).get("code") == -32002,
               f"expected -32002 w/o allowlist: {r1}")
        expect("observer.exec disabled" in r1.get("error", {}).get("message", ""),
               f"expected disabled message: {r1}")
    finally:
        shutdown(proc1)

    # ---- Pass 2: with allowlist → happy + forbidden ---------------------
    with tempfile.NamedTemporaryFile(
            "w", suffix=".allowlist", delete=False) as tf:
        tf.write("# smoke-test allowlist for observer.exec\n")
        tf.write("/bin/echo hello\n")
        tf.write("/bin/echo world\n")
        allowlist_path = tf.name
    try:
        env2 = dict(os.environ)
        env2["LDB_OBSERVER_EXEC_ALLOWLIST"] = allowlist_path
        env2.setdefault("LLDB_LOG_LEVEL", "error")
        proc2 = spawn(ldbd, env2)
        try:
            call = make_caller(proc2)

            # Happy: allowed argv → run and return stdout.
            r_ok = call("observer.exec",
                        {"argv": ["/bin/echo", "hello"]})
            expect(r_ok["ok"], f"happy path: {r_ok}")
            if r_ok["ok"]:
                d = r_ok["data"]
                expect(d.get("exit_code") == 0,
                       f"echo exit_code: {d.get('exit_code')}")
                expect(d.get("stdout") == "hello\n",
                       f"echo stdout: {d.get('stdout')!r}")
                expect("duration_ms" in d, f"missing duration_ms: {d}")

            # Disallowed argv → -32003.
            r_forbid = call("observer.exec",
                            {"argv": ["/bin/cat", "/etc/passwd"]})
            expect(not r_forbid["ok"], f"disallowed should error: {r_forbid}")
            expect(r_forbid.get("error", {}).get("code") == -32003,
                   f"disallowed should be -32003: {r_forbid}")

            # Relative argv[0] → -32602 even when an allowlist is loaded.
            r_rel = call("observer.exec",
                         {"argv": ["./bin/echo", "hello"]})
            expect(not r_rel["ok"], f"relative argv[0] should error: {r_rel}")
            expect(r_rel.get("error", {}).get("code") == -32602,
                   f"relative argv[0] should be -32602: {r_rel}")
        finally:
            shutdown(proc2)
    finally:
        try:
            os.unlink(allowlist_path)
        except OSError:
            pass

    if failures:
        for f in failures:
            sys.stderr.write(f"FAIL: {f}\n")
        sys.exit(1)
    print("observer.exec smoke test PASSED")


if __name__ == "__main__":
    main()
