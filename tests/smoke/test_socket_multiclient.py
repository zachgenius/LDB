#!/usr/bin/env python3
"""Validates accept-level concurrency + state persistence across connections.

§2 phase-2 of `docs/35-field-report-followups.md`. Phase-1 was
single-client: the accept loop served one connection to completion
before accepting the next. Phase-2 lifts the accept-level serialisation
so two `ldb --socket` clients can be CONNECTED to the daemon at the
same time, and each connection can persist target_id state across
its own RPC sequence.

Honesty note (post-review N6): this test does NOT pin "concurrent
dispatch." The dispatcher acquires `dispatch_mu_` for the entire
dispatch() lifetime, so overlapping RPCs are serialised at that
mutex. What this test DOES pin:

  - Accept-level concurrency: two connections can be open
    simultaneously. Phase-1 would block worker B's connect() until
    worker A disconnects; the barrier between target.open and
    module.list would then deadlock and time out at 10s.

  - State persistence across connections: each worker opens its OWN
    target_id, both succeed, both find their target still alive on
    the second RPC.

True per-connection dispatch parallelism is a phase-3 item (see
`docs/35-field-report-followups.md` "Phase 3 — carried forward").

Test sequence:
  1. Start `ldbd --listen unix:$sock` in the background.
  2. Two Python threads each open a unix-socket connection. Each
     runs a serial pair: `target.open` → `module.list`. A barrier
     between the two RPCs requires BOTH workers to reach it before
     either proceeds; a single-client accept loop deadlocks here.
  3. Notification isolation: phase-2 prereq has per-connection sinks
     so a stop notification fired on connection A doesn't show up in
     connection B's stream. The smoke fixture is statically linked
     and we don't actually run it, so this test focuses on the
     RPC-level happy path. Notification isolation is unit-tested at
     the runtime level (test_nonstop_runtime.cpp).
"""
import json
import os
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time


def read_stderr_nonblocking(proc, timeout: float = 0.2) -> bytes:
    if not proc.stderr:
        return b""
    try:
        ready, _, _ = select.select([proc.stderr], [], [], timeout)
    except (OSError, ValueError):
        return b""
    if not ready:
        return b""
    try:
        return proc.stderr.read1(4096) or b""
    except Exception:
        return b""


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


def jsonrpc_call(sock_file_w, sock_file_r, method, params):
    """Send one JSON-RPC request line, read one response line."""
    req = {"jsonrpc": "2.0", "id": "1", "method": method, "params": params}
    sock_file_w.write((json.dumps(req) + "\n").encode("utf-8"))
    sock_file_w.flush()
    line = sock_file_r.readline()
    if not line:
        raise IOError(f"socket closed during {method}")
    return json.loads(line)


def usage():
    sys.stderr.write(
        "usage: test_socket_multiclient.py <ldbd> <fixture>\n")
    sys.exit(2)


def main():
    if len(sys.argv) != 3:
        usage()
    ldbd, fixture = sys.argv[1], sys.argv[2]
    for path, label in [(ldbd, "ldbd"), (fixture, "fixture")]:
        if not os.path.exists(path):
            sys.stderr.write(f"{label} missing: {path}\n")
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
                err = read_stderr_nonblocking(daemon)
                sys.stderr.write(
                    f"daemon never bound socket; stderr={err!r}\n")
                sys.exit(1)

            # Barrier the two worker threads sync on between target.open
            # and module.list. Pins ACCEPT-level concurrency: in phase-1
            # the second worker's connect() would block on the daemon's
            # accept() until the first worker disconnects, so its
            # target.open never returns and the barrier hits its 10s
            # timeout. NOT pinning dispatch-level parallelism — that's
            # serialised by dispatch_mu_ in phase-2 and is a phase-3
            # refinement item.
            barrier = threading.Barrier(2, timeout=10.0)
            results = {}
            lock = threading.Lock()

            def worker(idx: int):
                try:
                    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    s.settimeout(30.0)
                    s.connect(sock_path)
                    rw = s.makefile("wb", buffering=0)
                    rr = s.makefile("rb", buffering=0)
                    try:
                        r1 = jsonrpc_call(rw, rr, "target.open",
                                          {"path": fixture})
                        # Sync up — both workers must reach this point
                        # before either runs the second RPC. Phase-1
                        # would block the second worker's connect()
                        # so its target.open never returns; the barrier
                        # would hit its 10s timeout.
                        try:
                            barrier.wait()
                        except threading.BrokenBarrierError:
                            with lock:
                                results[idx] = ("barrier-timeout", r1, None)
                            return

                        if not r1.get("ok"):
                            with lock:
                                results[idx] = ("target.open-fail", r1, None)
                            return

                        target_id = r1.get("data", {}).get("target_id")
                        if not isinstance(target_id, int):
                            with lock:
                                results[idx] = (
                                    "target.open-no-id", r1, None)
                            return

                        r2 = jsonrpc_call(rw, rr, "module.list",
                                          {"target_id": target_id})
                        with lock:
                            results[idx] = ("ok", r1, r2)
                    finally:
                        try:
                            rw.close()
                        except Exception:
                            pass
                        try:
                            rr.close()
                        except Exception:
                            pass
                        try:
                            s.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                        s.close()
                except Exception as e:
                    with lock:
                        results[idx] = (f"exception: {e}", None, None)

            t1 = threading.Thread(target=worker, args=(0,))
            t2 = threading.Thread(target=worker, args=(1,))
            t1.start()
            t2.start()
            t1.join(timeout=30.0)
            t2.join(timeout=30.0)
            expect(not t1.is_alive() and not t2.is_alive(),
                   "worker thread did not exit within 30s — likely "
                   "deadlocked on the accept() loop")

            for idx in (0, 1):
                r = results.get(idx)
                expect(r is not None, f"worker {idx} produced no result")
                if r is None:
                    continue
                status, r1, r2 = r
                expect(status == "ok",
                       f"worker {idx}: status={status} r1={r1!r}")
                if status == "ok":
                    expect(r1.get("ok") is True,
                           f"worker {idx}: target.open not ok: {r1!r}")
                    expect(r2.get("ok") is True,
                           f"worker {idx}: module.list not ok: {r2!r}")
                    expect("modules" in r2.get("data", {}),
                           f"worker {idx}: missing modules in {r2!r}")
        finally:
            try:
                daemon.send_signal(signal.SIGTERM)
                daemon.wait(timeout=5)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait(timeout=2)

    if failures:
        sys.stderr.write("FAILURES:\n")
        for f in failures:
            sys.stderr.write(f"  - {f}\n")
        sys.exit(1)
    print("OK: two clients held concurrent connections; per-connection "
          "target state persisted across the RPC pair")


if __name__ == "__main__":
    main()
