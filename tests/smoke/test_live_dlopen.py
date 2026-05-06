#!/usr/bin/env python3
"""Smoke test for dlopen-invalidation of <layout_digest> — slice 1c.

Closes the 1b reviewer finding A2 (dlopen-without-resume gap):
two snapshots bracketing a dlopen() must produce different
`_provenance.snapshot` strings — even though `<gen>` did not bump
between them — so an agent can detect that the address-space layout
has changed.

Test arc (cross-daemon — the user-facing contract):
  1. Spawn dlopener fixture; it prints PID + READY=PRE_DLOPEN, then
     pauses waiting for SIGUSR1.
  2. Daemon attaches by PID, captures snapshot S1 (pre-dlopen layout)
     + module.list (the libpthread baseline).
  3. Daemon detaches; harness SIGUSR1s the inferior; inferior
     dlopen()s libpthread, prints READY=POST_DLOPEN, pauses again.
  4. Fresh daemon attaches, captures S2.
  5. Assert S1.layout_digest != S2.layout_digest AND module.list
     post contains libpthread.

The slice-1c snapshot shape is
    live:<gen>:<reg_digest>:<layout_digest>:<bp_digest>
We extract layout_digest as the third colon-delimited segment.

Why cross-daemon and not single-daemon: the single-daemon arc would
exercise the SBListener machinery directly (cache invalidates on the
in-process event), but reliably stopping the inferior at a
post-dlopen point (without already-loaded libpthread shadowing the
test) needs a step-/breakpoint dance that's brittle across LLDB
versions. The cross-daemon arc captures the user-visible contract
and is what the determinism gate cares about; single-daemon
invalidation is exercised indirectly by every snapshot call (which
unconditionally drains events). See worklog for the deferral.

If libpthread is already loaded in the dlopener's process before
dlopen() runs (some glibc layouts), the test SKIPs cleanly.
"""
import json
import os
import re
import signal
import subprocess
import sys
import time


LIVE_RE = re.compile(r"^live:([0-9]+):([0-9a-f]{64}):([0-9a-f]{64}):([0-9a-f]{64})$")


def usage():
    sys.stderr.write("usage: test_live_dlopen.py <ldbd> <dlopener>\n")
    sys.exit(2)


class Daemon:
    def __init__(self, ldbd):
        env = dict(os.environ)
        env.setdefault("LLDB_LOG_LEVEL", "error")
        self.proc = subprocess.Popen(
            [ldbd, "--stdio", "--log-level", "error"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env, text=True, bufsize=1,
        )
        self._next_id = 0

    def call(self, method, params=None):
        self._next_id += 1
        rid = f"r{self._next_id}"
        req = {"jsonrpc": "2.0", "id": rid, "method": method,
               "params": params or {}}
        self.proc.stdin.write(json.dumps(req) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            err = self.proc.stderr.read()
            raise RuntimeError(f"daemon closed stdout (stderr was: {err})")
        return json.loads(line)

    def close(self):
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=10)
        except Exception:
            self.proc.kill()
            self.proc.wait()


def wait_for_marker(p, marker, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        line = p.stdout.readline()
        if not line:
            return None
        if marker in line:
            return line
    return None


def parse_layout(snap):
    m = LIVE_RE.match(snap)
    if not m:
        return None
    return m.group(3)


def main():
    if len(sys.argv) != 3:
        usage()
    ldbd, dlopener = sys.argv[1], sys.argv[2]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n"); sys.exit(1)
    if not os.path.isfile(dlopener):
        sys.stderr.write(f"dlopener missing: {dlopener}\n"); sys.exit(1)

    inferior = subprocess.Popen(
        [dlopener], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True,
    )
    failures = []

    def expect(cond, msg):
        if not cond:
            failures.append(msg)

    try:
        line = wait_for_marker(inferior, "READY=PRE_DLOPEN", timeout=5.0)
        if line is None:
            sys.stderr.write("dlopener didn't print READY=PRE_DLOPEN\n")
            sys.exit(1)
        pid_token = line.split()[0]
        inferior_pid = int(pid_token[len("PID="):])

        # Pre-dlopen attach.
        d = Daemon(ldbd)
        try:
            r = d.call("target.create_empty", {})
            expect(r["ok"], f"target.create_empty: {r}")
            target_id = r["data"]["target_id"]
            r = d.call("target.attach",
                       {"target_id": target_id, "pid": inferior_pid})
            expect(r["ok"], f"target.attach pre: {r}")
            if not r["ok"]:
                raise RuntimeError("attach failed")
            snap_pre = r["_provenance"]["snapshot"]
            layout_pre = parse_layout(snap_pre)
            expect(layout_pre is not None,
                   f"snap shape mismatch pre: {snap_pre!r}")

            ml_pre = d.call("module.list", {"target_id": target_id})
            modules_pre = {m["path"]
                           for m in ml_pre["data"].get("modules", [])
                           if m.get("path")}

            if any("libpthread" in p for p in modules_pre):
                print("SKIP: libpthread.so already loaded pre-dlopen")
                d.call("process.detach", {"target_id": target_id})
                return

            d.call("process.detach", {"target_id": target_id})
        finally:
            d.close()

        # Kick the inferior past pause(); it will dlopen libpthread
        # and pause() again in its second wait-loop.
        os.kill(inferior_pid, signal.SIGUSR1)
        line = wait_for_marker(inferior, "READY=POST_DLOPEN", timeout=5.0)
        if line is None:
            sys.stderr.write("dlopener didn't print READY=POST_DLOPEN\n")
            sys.exit(1)

        # Post-dlopen attach (fresh daemon).
        d2 = Daemon(ldbd)
        try:
            r = d2.call("target.create_empty", {})
            target_id2 = r["data"]["target_id"]
            r = d2.call("target.attach",
                        {"target_id": target_id2, "pid": inferior_pid})
            expect(r["ok"], f"target.attach post: {r}")
            if not r["ok"]:
                raise RuntimeError("attach post failed")
            snap_post = r["_provenance"]["snapshot"]
            layout_post = parse_layout(snap_post)
            expect(layout_post is not None,
                   f"snap shape mismatch post: {snap_post!r}")

            ml_post = d2.call("module.list", {"target_id": target_id2})
            modules_post = {m["path"]
                            for m in ml_post["data"].get("modules", [])
                            if m.get("path")}
            expect(any("libpthread" in p for p in modules_post),
                   f"libpthread NOT in post-dlopen module.list "
                   f"({len(modules_post)} modules)")
            expect(layout_pre != layout_post,
                   f"layout_digest unchanged across dlopen — slice-1c "
                   f"invariant FAILED:\n  pre={snap_pre}\n  post={snap_post}")

            d2.call("process.detach", {"target_id": target_id2})
        finally:
            d2.close()
    finally:
        try: inferior.kill()
        except Exception: pass
        try: inferior.wait(timeout=5)
        except Exception: pass

    if failures:
        for f in failures:
            sys.stderr.write(f"FAIL: {f}\n")
        sys.exit(1)
    print("dlopen layout_digest invalidation PASSED (cross-daemon)")


if __name__ == "__main__":
    main()
