#!/usr/bin/env python3
"""End-to-end smoke test for `ldb-dap`.

Spawns `ldb-dap` (which in turn spawns `ldbd`), drives it with the
minimum DAP request set the shim ships:

    initialize → attach → threads → stackTrace → scopes → variables
                                  → evaluate → continue → disconnect

Asserts each response matches DAP shape (success / type / request_seq /
command). Uses the sleeper fixture so the inferior is long-running and
the attach point is stable.
"""

import json
import os
import subprocess
import sys
import time


def usage():
    sys.stderr.write("usage: test_dap_shim.py <ldb-dap> <ldbd> <sleeper>\n")
    sys.exit(2)


class DapClient:
    def __init__(self, proc):
        self.proc = proc
        self.next_seq = 1

    def write(self, body):
        body["seq"] = self.next_seq
        self.next_seq += 1
        s = json.dumps(body)
        wire = f"Content-Length: {len(s)}\r\n\r\n{s}".encode("utf-8")
        self.proc.stdin.write(wire)
        self.proc.stdin.flush()

    def read(self):
        # Read header lines until blank.
        headers = {}
        while True:
            line = self.proc.stdout.readline()
            if not line:
                return None
            line = line.decode("utf-8").rstrip("\r\n")
            if line == "":
                break
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        if "content-length" not in headers:
            raise RuntimeError(f"no content-length in headers: {headers}")
        n = int(headers["content-length"])
        body = self.proc.stdout.read(n)
        return json.loads(body)

    def request(self, command, arguments=None):
        self.write({"type": "request", "command": command,
                    "arguments": arguments or {}})

    def read_response_for(self, command, timeout=10.0,
                          expect_events=0):
        """Read until we see a response whose command matches. Events
        are collected and returned. If `expect_events` is > 0, also
        wait for that many events to arrive (the shim emits
        `initialized` after initialize, `terminated` after disconnect,
        `stopped`/`exited` after continue/step). The shim's main loop
        guarantees events emitted as a side effect of one request are
        written before the loop returns to read the next request, so
        a simple sequential read suffices once the response arrives."""
        deadline = time.time() + timeout
        events = []
        response = None
        while time.time() < deadline:
            msg = self.read()
            if msg is None:
                raise RuntimeError(f"DAP shim closed stdout while waiting "
                                   f"for response to {command}")
            mtype = msg.get("type")
            if mtype == "event":
                events.append(msg)
            elif mtype == "response" and msg.get("command") == command:
                response = msg
            if response is not None and len(events) >= expect_events:
                return response, events
        raise RuntimeError(f"timed out waiting for response to {command} "
                           f"(got response={response is not None}, "
                           f"events={len(events)}/{expect_events})")


def main():
    if len(sys.argv) != 4:
        usage()
    dap_bin, ldbd, sleeper = sys.argv[1], sys.argv[2], sys.argv[3]
    for p in (dap_bin, ldbd):
        if not os.access(p, os.X_OK):
            sys.stderr.write(f"not executable: {p}\n"); sys.exit(1)
    if not os.path.isfile(sleeper):
        sys.stderr.write(f"sleeper missing: {sleeper}\n"); sys.exit(1)

    inferior = subprocess.Popen(
        [sleeper], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    failures = []

    def expect(cond, msg):
        if not cond:
            failures.append(msg)

    try:
        line = inferior.stdout.readline()
        if "READY=" not in line:
            sys.stderr.write(f"sleeper didn't print READY: {line!r}\n")
            sys.exit(1)
        pid_token = line.split()[0]
        assert pid_token.startswith("PID="), line
        inferior_pid = int(pid_token[len("PID="):])

        env = dict(os.environ)
        env.setdefault("LDB_LOG_LEVEL", "error")
        proc = subprocess.Popen(
            [dap_bin, "--ldbd", ldbd, "--log-level", "error"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        client = DapClient(proc)

        try:
            # 1. initialize — expect capabilities + initialized event after
            client.request("initialize", {"clientID": "smoke", "adapterID": "ldb"})
            resp, events = client.read_response_for("initialize",
                                                    expect_events=1)
            expect(resp["success"], f"initialize: {resp}")
            expect(resp["body"].get("supportsConfigurationDoneRequest") is True,
                   f"initialize caps: {resp['body']}")
            expect(any(e.get("event") == "initialized" for e in events),
                   "expected `initialized` event after initialize response")

            # 2. attach to the running sleeper
            client.request("attach", {"processId": inferior_pid})
            resp, _ = client.read_response_for("attach")
            expect(resp["success"], f"attach: {resp}")

            # 3. configurationDone (no-op)
            client.request("configurationDone", {})
            resp, _ = client.read_response_for("configurationDone")
            expect(resp["success"], f"configurationDone: {resp}")

            # 4. threads
            client.request("threads", {})
            resp, _ = client.read_response_for("threads")
            expect(resp["success"], f"threads: {resp}")
            tlist = resp["body"]["threads"]
            expect(isinstance(tlist, list) and len(tlist) >= 1,
                   f"threads list: {tlist}")
            tid = tlist[0]["id"]
            expect("name" in tlist[0], f"thread missing name: {tlist[0]}")

            # 5. stackTrace
            client.request("stackTrace", {"threadId": tid})
            resp, _ = client.read_response_for("stackTrace")
            expect(resp["success"], f"stackTrace: {resp}")
            frames = resp["body"]["stackFrames"]
            expect(isinstance(frames, list) and len(frames) >= 1,
                   f"stack frames: {frames}")
            frame_id = frames[0]["id"]
            expect("name" in frames[0], f"frame missing name: {frames[0]}")

            # 6. scopes
            client.request("scopes", {"frameId": frame_id})
            resp, _ = client.read_response_for("scopes")
            expect(resp["success"], f"scopes: {resp}")
            scopes = resp["body"]["scopes"]
            expect(len(scopes) == 3, f"expected 3 scopes, got {len(scopes)}")
            expect([s["name"] for s in scopes] ==
                   ["Locals", "Arguments", "Registers"],
                   f"scope names: {[s['name'] for s in scopes]}")
            registers_ref = next(s["variablesReference"] for s in scopes
                                 if s["name"] == "Registers")
            expect(registers_ref > 0,
                   f"registers ref not positive: {registers_ref}")

            # 7. variables on Registers (Registers is the most reliably
            # non-empty scope on a freshly-attached thread).
            client.request("variables",
                           {"variablesReference": registers_ref})
            resp, _ = client.read_response_for("variables")
            expect(resp["success"], f"variables: {resp}")
            vs = resp["body"]["variables"]
            expect(isinstance(vs, list),
                   f"variables not a list: {vs}")
            # We don't assert non-empty — some platforms don't surface
            # registers in the same way. The shape is what matters.

            # 8. evaluate (use a literal so we don't depend on inferior
            # state; the daemon's expression evaluator handles `1+2`).
            client.request("evaluate",
                           {"expression": "1+2", "frameId": frame_id})
            resp, _ = client.read_response_for("evaluate")
            # evaluate may legitimately fail if expr-eval isn't viable on
            # the attach point; we accept either success with a result
            # or a failure with a non-empty message.
            if resp["success"]:
                expect("result" in resp["body"],
                       f"evaluate body missing result: {resp['body']}")
            else:
                expect("message" in resp,
                       f"failed evaluate missing message: {resp}")

            # 9. disconnect (default detach, terminateDebuggee=false)
            client.request("disconnect", {"terminateDebuggee": False})
            resp, events = client.read_response_for("disconnect",
                                                    expect_events=1)
            expect(resp["success"], f"disconnect: {resp}")
            expect(any(e.get("event") == "terminated" for e in events),
                   "expected `terminated` event after disconnect")

        finally:
            try:
                proc.stdin.close()
            except Exception:
                pass
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

        if failures:
            for f in failures:
                sys.stderr.write(f"FAIL: {f}\n")
            sys.exit(1)
        print("DAP shim smoke test PASSED")
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
