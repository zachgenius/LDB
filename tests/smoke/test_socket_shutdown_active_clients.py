#!/usr/bin/env python3
"""Smoke test: §2 phase-2 I2 — active workers gate on the shutdown latch.

Before the I2 fix, `daemon.shutdown` set `g_shutdown` and woke the
accept loop, but already-connected workers kept reading and
dispatching forever as long as the peer kept sending. The phase-2
docs claim "shutdown stops accepting new RPCs immediately"; the
actual behaviour was broader. The dispatcher acted on every
post-shutdown RPC and let the daemon process linger long after the
listener had stopped accepting new connections.

Fix: between read and dispatch in `serve_one_connection`, check
the daemon's shutdown gate. If set, synthesise a kBadState response
("daemon shutting down") instead of dispatching, then break out of
the loop. The daemon then joins the worker and exits.

Test sequence:
  1. Start `ldbd --listen unix:$sock` in the background.
  2. Open TWO concurrent unix-socket connections (A and B).
  3. A does a sanity `hello` so we know it's serviceable.
  4. B sends `daemon.shutdown`, gets ok=true, closes.
  5. A sends another RPC. We expect either:
       (a) a typed error response naming the shutdown condition
           ("shutting down" / "shutdown" / kBadState -32002), OR
       (b) the connection closed without a reply (socket EOF).
     Both are correct behaviours; the pre-fix bug was a normal
     success response (the RPC was actually dispatched).
  6. The daemon must exit within a generous window.
"""
import json
import os
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time


def wait_for_socket(path: str, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(path):
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect(path)
                s.close()
                return True
            except OSError:
                pass
        time.sleep(0.05)
    return False


def usage():
    sys.stderr.write(
        "usage: test_socket_shutdown_active_clients.py <ldbd>\n")
    sys.exit(2)


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

    with tempfile.TemporaryDirectory() as tmp:
        sock_path = os.path.join(tmp, "ldbd.sock")
        daemon = subprocess.Popen(
            [ldbd, "--listen", f"unix:{sock_path}", "--log-level", "error"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            if not wait_for_socket(sock_path, timeout=5.0):
                sys.stderr.write("daemon never bound socket\n")
                sys.exit(1)

            # Connection A — a stable connection that survives the
            # daemon.shutdown.
            sock_a = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock_a.settimeout(10.0)
            sock_a.connect(sock_path)
            rw_a = sock_a.makefile("wb", buffering=0)
            rr_a = sock_a.makefile("rb", buffering=0)

            # Sanity: A is serviceable pre-shutdown.
            rw_a.write((json.dumps({
                "jsonrpc": "2.0", "id": "a1", "method": "hello",
                "params": {}}) + "\n").encode("utf-8"))
            rw_a.flush()
            line = rr_a.readline()
            expect(bool(line), "A's pre-shutdown hello got no response")
            try:
                pre = json.loads(line)
                expect(pre.get("ok") is True,
                       f"A pre-shutdown hello not ok: {pre!r}")
            except json.JSONDecodeError:
                failures.append(f"A pre-shutdown hello not JSON: {line!r}")

            # Connection B — fires daemon.shutdown and closes.
            sock_b = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock_b.settimeout(5.0)
            sock_b.connect(sock_path)
            rw_b = sock_b.makefile("wb", buffering=0)
            rr_b = sock_b.makefile("rb", buffering=0)
            rw_b.write((json.dumps({
                "jsonrpc": "2.0", "id": "b1", "method": "daemon.shutdown",
                "params": {}}) + "\n").encode("utf-8"))
            rw_b.flush()
            line_b = rr_b.readline()
            expect(bool(line_b), "B got no response to daemon.shutdown")
            try:
                shut = json.loads(line_b)
                expect(shut.get("ok") is True,
                       f"daemon.shutdown not ok: {shut!r}")
            except json.JSONDecodeError:
                failures.append(
                    f"daemon.shutdown reply not JSON: {line_b!r}")
            try:
                rw_b.close()
                rr_b.close()
                sock_b.shutdown(socket.SHUT_RDWR)
                sock_b.close()
            except OSError:
                pass

            # A now sends another RPC. Pre-fix behaviour: it succeeds.
            # Post-fix behaviour: kBadState error OR clean EOF (peer
            # close after writing the error). Either is acceptable;
            # the bug is a normal success response.
            try:
                rw_a.write((json.dumps({
                    "jsonrpc": "2.0", "id": "a2", "method": "hello",
                    "params": {}}) + "\n").encode("utf-8"))
                rw_a.flush()
            except OSError:
                # Daemon closed our side before we could write — also
                # an acceptable shutdown signal.
                pass

            try:
                line_a = rr_a.readline()
            except OSError:
                line_a = b""

            if line_a:
                try:
                    resp = json.loads(line_a)
                except json.JSONDecodeError:
                    failures.append(
                        f"A post-shutdown response not JSON: {line_a!r}")
                    resp = None
                if resp is not None:
                    ok = resp.get("ok")
                    if ok is True:
                        # The bug: daemon kept servicing post-shutdown.
                        failures.append(
                            f"A post-shutdown hello was serviced "
                            f"successfully (expected shutdown error): "
                            f"{resp!r}")
                    else:
                        err = resp.get("error", {})
                        code = err.get("code")
                        msg = err.get("message", "").lower()
                        expect(
                            code == -32002 or
                            "shut" in msg or "down" in msg,
                            f"A post-shutdown error not a shutdown "
                            f"diagnostic: code={code} msg={msg!r}")

            try:
                rw_a.close()
                rr_a.close()
                sock_a.shutdown(socket.SHUT_RDWR)
                sock_a.close()
            except OSError:
                pass

            # Daemon must exit within a generous window. Pre-fix the
            # worker on A would keep the daemon alive indefinitely.
            try:
                rc = daemon.wait(timeout=10.0)
                expect(rc == 0, f"daemon rc={rc}, expected 0")
            except subprocess.TimeoutExpired:
                failures.append(
                    "daemon did not exit within 10s after "
                    "daemon.shutdown — workers are not gating on the "
                    "shutdown latch")
        finally:
            if daemon.poll() is None:
                daemon.send_signal(signal.SIGTERM)
                try:
                    daemon.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    daemon.kill()

    if failures:
        sys.stderr.write("FAILURES:\n")
        for f in failures:
            sys.stderr.write(f"  - {f}\n")
        sys.exit(1)
    print("OK: workers gate on the shutdown latch; daemon exits "
          "promptly even with an active connection")


if __name__ == "__main__":
    main()
