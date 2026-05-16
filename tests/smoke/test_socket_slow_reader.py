#!/usr/bin/env python3
"""Smoke test: §2 phase-2 I3 — SO_SNDTIMEO bounds slow-reader stalls.

Before the I3 fix the accept block set SO_RCVTIMEO on each connection
but never SO_SNDTIMEO. A connected-but-not-reading client lets the
kernel send buffer fill; the daemon's `::write(2)` in the streambuf's
sync() then blocks indefinitely, holding `map_mu_` shared on the
inner backend mutex. Worse: when the next client calls `target.close`
on a different target, that path takes `map_mu_` UNIQUE while
holding `dispatch_mu_`. The whole daemon wedges — accept still
runs but every RPC sits behind the dead-peer write.

Fix: mirror the SO_RCVTIMEO block. 60 seconds is generous enough
that nothing benign trips it, tight enough that a bad peer doesn't
hang the daemon for minutes. On EAGAIN the streambuf's
write_failed_ latch closes the connection cleanly.

Test sequence:
  1. Start `ldbd --listen unix:$sock`.
  2. Connect client A. Do NOT read responses from it. Send many
     RPCs ('hello' or 'describe.endpoints') as fast as we can
     write — the kernel's per-socket send buffer is ~16KB-256KB
     so it fills quickly. The daemon's responses pile up in its
     write buffer; eventually one ::write() blocks.
  3. Connect client B. Send one hello + read the response. With
     the fix, this works promptly (under SO_SNDTIMEO + worker
     spawn overhead). Without the fix, B's read can hang well
     past the test budget — phase 2 already shipped the
     dispatch_mu_ recursive mutex which means B's worker may
     still get a slot, but a `target.close` race could wedge.
     We focus on the bounded-time invariant: A's response-write
     stall must NOT exceed the SO_SNDTIMEO budget.
  4. Daemon must shut down cleanly via SIGTERM within a generous
     window after we stop reading.
"""
import json
import os
import select
import signal
import socket
import subprocess
import sys
import tempfile
import threading
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
        "usage: test_socket_slow_reader.py <ldbd>\n")
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

            # Client A — the slow reader. We connect, fire many
            # requests, never read responses. The daemon's send
            # buffer fills; eventually its ::write() either blocks
            # or trips SO_SNDTIMEO.
            sock_a = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock_a.settimeout(2.0)
            # Shrink A's receive buffer so the daemon's send-side
            # back-pressures faster. Default is platform-dependent;
            # smaller buffer = faster fill.
            try:
                sock_a.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            except OSError:
                pass
            sock_a.connect(sock_path)
            rw_a = sock_a.makefile("wb", buffering=0)
            # describe.endpoints emits a large response (~50KB) — ten
            # of those swamps any kernel send buffer.
            big = (json.dumps({
                "jsonrpc": "2.0", "id": "a",
                "method": "describe.endpoints",
                "params": {}}) + "\n").encode("utf-8")
            try:
                for _ in range(100):
                    rw_a.write(big)
            except OSError:
                # Daemon's read side may already be back-pressured
                # if we filled both directions; the test is about
                # the daemon's write side.
                pass

            # Client B — should still be serviceable promptly.
            start_b = time.monotonic()
            sock_b = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock_b.settimeout(10.0)
            sock_b.connect(sock_path)
            rw_b = sock_b.makefile("wb", buffering=0)
            rr_b = sock_b.makefile("rb", buffering=0)
            rw_b.write((json.dumps({
                "jsonrpc": "2.0", "id": "b1", "method": "hello",
                "params": {}}) + "\n").encode("utf-8"))
            rw_b.flush()
            line_b = rr_b.readline()
            elapsed_b = time.monotonic() - start_b
            expect(bool(line_b),
                   "B got no response to hello while A was a slow reader")
            try:
                resp_b = json.loads(line_b)
                expect(resp_b.get("ok") is True,
                       f"B's hello reply not ok: {resp_b!r}")
            except json.JSONDecodeError:
                failures.append(f"B's hello reply not JSON: {line_b!r}")
            # Under the I3 fix B's hello should complete within a few
            # seconds. We give it 30s as a safety margin — the goal is
            # to detect "indefinitely stuck", not benchmark.
            expect(elapsed_b < 30.0,
                   f"B's hello took {elapsed_b:.1f}s — likely wedged "
                   f"behind A's send-buffer stall")

            try:
                rw_b.close()
                rr_b.close()
                sock_b.shutdown(socket.SHUT_RDWR)
                sock_b.close()
            except OSError:
                pass

            # Tear down A without reading any of its backed-up replies.
            # With SO_SNDTIMEO the daemon's write to A times out
            # (EAGAIN), the streambuf latches write_failed_,
            # serve_one_connection's write_response throws Error, and
            # the worker exits cleanly. Without SO_SNDTIMEO the worker
            # stays blocked in the write — daemon shutdown below
            # would have to fall back to the 300s SO_RCVTIMEO (which
            # never fires because the write blocks first).
            try:
                rw_a.close()
                sock_a.shutdown(socket.SHUT_RDWR)
                sock_a.close()
            except OSError:
                pass

            # Daemon must shut down promptly.
            daemon.send_signal(signal.SIGTERM)
            try:
                rc = daemon.wait(timeout=15.0)
                expect(rc == 0, f"daemon rc={rc}, expected 0")
            except subprocess.TimeoutExpired:
                failures.append(
                    "daemon did not exit within 15s after SIGTERM — "
                    "likely wedged on a blocked write to slow reader")
        finally:
            if daemon.poll() is None:
                daemon.kill()
                try:
                    daemon.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    pass

    if failures:
        sys.stderr.write("FAILURES:\n")
        for f in failures:
            sys.stderr.write(f"  - {f}\n")
        sys.exit(1)
    print("OK: B's RPC completed promptly despite A being a slow "
          "reader; daemon shut down cleanly")


if __name__ == "__main__":
    main()
