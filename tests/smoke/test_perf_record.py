#!/usr/bin/env python3
"""Smoke test for perf.record / perf.report / perf.cancel (post-V1 #13).

SKIPS cleanly when:
  - `perf` is not on PATH (no linux-tools installed), or
  - kernel.perf_event_paranoid is too strict and `perf stat -e cycles
    /bin/true` exits non-zero.

When live:
  - Records a 500 ms cycles trace of ldb_fix_sleeper.
  - Asserts the response carries artifact_id > 0, sample_count > 0, and
    that perf.report against that artifact returns at least one sample
    whose stack frame array is non-empty.
  - Asserts the perf.cancel endpoint returns kBadState in this phase-1
    build (synchronous record; nothing in flight).

Phase-1 contract per docs/22-perf-integration.md.
"""
import json
import os
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time


def usage():
    sys.stderr.write("usage: test_perf_record.py <ldbd> <sleeper>\n")
    sys.exit(2)


def skip(msg):
    sys.stderr.write(f"SKIP: {msg}\n")
    print(f"perf smoke test SKIPPED: {msg}")
    sys.exit(0)


def perf_usable():
    if shutil.which("perf") is None:
        return False, "perf not on PATH"
    # `perf stat -e cycles /bin/true` is the canonical "is perf
    # functional in this environment" probe — fails on paranoid > 1
    # without CAP_SYS_ADMIN.
    try:
        r = subprocess.run(
            ["perf", "stat", "-e", "cycles", "/bin/true"],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            timeout=10,
        )
    except FileNotFoundError:
        return False, "perf not on PATH"
    except subprocess.TimeoutExpired:
        return False, "perf stat timed out"
    if r.returncode != 0:
        err = (r.stderr or b"").decode("utf-8", "replace").strip()
        return False, f"perf stat rc={r.returncode}: {err.splitlines()[-1] if err else ''}"
    return True, "ok"


def main():
    if len(sys.argv) != 3:
        usage()
    ldbd, sleeper = sys.argv[1], sys.argv[2]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n")
        sys.exit(1)
    if not os.access(sleeper, os.X_OK):
        sys.stderr.write(f"sleeper not executable: {sleeper}\n")
        sys.exit(1)

    ok, why = perf_usable()
    if not ok:
        skip(why)

    store_root = tempfile.mkdtemp(prefix="ldb_smoke_perf_")
    # Spawn a CPU-busy subprocess as the recording target.
    #
    # The sleeper fixture sits idle, which produces zero samples on
    # hosts where `perf_event_paranoid` forces hardware `cycles` to
    # fall back to software `task-clock` (e.g. GitHub Actions Linux
    # runners). task-clock only ticks while the target is on-CPU, so
    # a sleeping pid would yield an empty trace and crash the smoke
    # at `samples[0]`. A Python busy-loop guarantees enough on-CPU
    # time for either `cycles` or `task-clock` to produce samples in
    # the 500ms record window.
    target_proc = subprocess.Popen(
        ["python3", "-u", "-c",
         "import time,math,sys;"
         "print('READY=BUSY',flush=True);"
         "t0=time.time();"
         "s=0.0;"
         # Run longer than the record window so perf still has work
         # to sample at the end. We don't kill the loop ourselves;
         # the smoke's `finally` reaps via SIGTERM.
         "import os;\n"
         "while time.time()-t0 < 5.0: s += math.sin(s) + 1.0; pass"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        # Wait for the busy-loop to acknowledge it's running.
        ready_line = target_proc.stdout.readline().decode("utf-8", "replace")
        if "READY=" not in ready_line:
            sys.stderr.write(
                f"busy-loop didn't print READY: {ready_line!r}\n")
            sys.exit(1)
        target_pid = target_proc.pid
        # Note: <sleeper> argv is accepted for backwards compat with
        # tests/CMakeLists.txt; the previous design recorded it, the
        # current one records the busy-loop above. Reference `sleeper`
        # once so the unused-name warning doesn't fire.
        _ = sleeper

        env = dict(os.environ)
        env["LDB_STORE_ROOT"] = store_root
        env.setdefault("LLDB_LOG_LEVEL", "error")
        daemon = subprocess.Popen(
            [ldbd, "--stdio", "--log-level", "error"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=env, text=True, bufsize=1,
        )

        next_id = [0]
        def call(method, params=None, timeout=15):
            next_id[0] += 1
            rid = f"r{next_id[0]}"
            req = {"jsonrpc": "2.0", "id": rid, "method": method,
                   "params": params or {}}
            daemon.stdin.write(json.dumps(req) + "\n")
            daemon.stdin.flush()
            # Bound the per-call wait so a daemon hang (perf segfaults
            # mid-record, waitpid blocks indefinitely) surfaces as a real
            # test failure rather than ctest's outer TIMEOUT verdict —
            # the two are diagnostically different.
            ready, _, _ = select.select([daemon.stdout], [], [], timeout)
            if not ready:
                try:
                    daemon.kill()
                except Exception:
                    pass
                stderr = ""
                try:
                    stderr = daemon.stderr.read() or ""
                except Exception:
                    pass
                sys.stderr.write(
                    f"daemon did not respond to {method} within "
                    f"{timeout}s (stderr tail: {stderr[-2000:]})\n")
                sys.exit(1)
            line = daemon.stdout.readline()
            if not line:
                stderr = daemon.stderr.read()
                sys.stderr.write(
                    f"daemon closed stdout (stderr was: {stderr})\n")
                sys.exit(1)
            return json.loads(line)

        failures = []
        def expect(cond, msg):
            if not cond:
                failures.append(msg)

        try:
            # ---- describe.endpoints surfaces perf.* ----
            r0 = call("describe.endpoints")
            expect(r0["ok"], f"describe.endpoints: {r0}")
            methods = {e["method"] for e in r0["data"]["endpoints"]}
            for m in ("perf.record", "perf.report", "perf.cancel"):
                expect(m in methods, f"{m} missing from describe.endpoints")

            # ---- perf.cancel: phase-1 returns kBadState ----
            rc = call("perf.cancel", {"record_id": "r1"})
            expect(not rc["ok"], f"perf.cancel should fail in phase 1: {rc}")
            expect(rc.get("error", {}).get("code") == -32002,
                   f"perf.cancel rc should be kBadState: {rc}")

            # ---- perf.record: param validation ----
            rinv = call("perf.record", {})  # missing both pid and command
            expect(not rinv["ok"] and rinv.get("error",{}).get("code") == -32602,
                   f"perf.record empty -> -32602: {rinv}")

            rinv2 = call("perf.record", {"pid": target_pid})  # missing duration_ms
            expect(not rinv2["ok"] and rinv2.get("error",{}).get("code") == -32602,
                   f"perf.record without duration -> -32602: {rinv2}")

            # ---- perf.record: live happy path ----
            rec = call("perf.record", {
                "pid":         target_pid,
                "duration_ms": 500,
                "frequency_hz":99,
                "events":      ["cycles"],
                "call_graph":  "fp",
            }, timeout=20)
            if not rec["ok"]:
                # If perf records on this kernel still need privileges
                # beyond what `perf stat` does, surface the SKIP rather
                # than a noisy failure.
                msg = rec.get("error", {}).get("message", "")
                if "permission" in msg.lower() or "paranoid" in msg.lower():
                    skip(f"perf record needs more privs than perf stat: {msg}")
                expect(False, f"perf.record live: {rec}")
            else:
                data = rec["data"]
                expect(int(data["artifact_id"]) > 0,
                       f"artifact_id must be positive: {data}")
                expect(int(data["sample_count"]) > 0,
                       f"sample_count must be > 0: {data}")
                expect(isinstance(data.get("perf_argv"), list)
                       and any("record" in a for a in data["perf_argv"]),
                       f"perf_argv missing 'record': {data}")

                # ---- perf.report against the same artifact ----
                rep = call("perf.report", {
                    "artifact_id": int(data["artifact_id"]),
                    "max_samples": 20,
                }, timeout=20)
                expect(rep["ok"], f"perf.report: {rep}")
                if rep["ok"]:
                    samples = rep["data"]["samples"]
                    expect(len(samples) > 0,
                           f"perf.report should return samples: {rep}")
                    # At least one sample stack is non-empty.
                    have_stack = any(len(s.get("stack", [])) > 0
                                     for s in samples)
                    expect(have_stack,
                           "no sample had a non-empty stack frame array")
                    # Shape check: first sample has the expected keys.
                    s0 = samples[0]
                    for k in ("ts_ns", "tid", "pid", "cpu", "event", "stack"):
                        expect(k in s0,
                               f"sample missing field {k!r}: {s0}")
                    if s0.get("stack"):
                        f0 = s0["stack"][0]
                        expect("addr" in f0,
                               f"stack frame missing addr: {f0}")

        finally:
            try:
                daemon.stdin.close()
            except Exception:
                pass
            try:
                daemon.wait(timeout=10)
            except subprocess.TimeoutExpired:
                daemon.kill()

        if failures:
            for f in failures:
                sys.stderr.write(f"FAIL: {f}\n")
            sys.exit(1)
        print("perf smoke test PASSED")
    finally:
        # Kill the sleeper.
        try:
            target_proc.send_signal(signal.SIGTERM)
            target_proc.wait(timeout=5)
        except Exception:
            try:
                target_proc.kill()
            except Exception:
                pass
        shutil.rmtree(store_root, ignore_errors=True)


if __name__ == "__main__":
    main()
