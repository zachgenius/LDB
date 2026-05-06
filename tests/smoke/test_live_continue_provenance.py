#!/usr/bin/env python3
"""process.continue round-trip provenance — slice 1c arc A3.

Closes the 1b reviewer finding "no process.continue round-trip in 1b's
smoke test". 1b's smoke uses step_thread which absorbs the SIGSTOP-tracer
cycle; this gate exercises the real run-to-bp path:

  1. Open the looper fixture (work_step called in a hot loop in main).
  2. Set a breakpoint on work_step via probe.create
     (kind=lldb_breakpoint, action=stop).
  3. process.launch (no stop_at_entry) — runs to the first work_step
     hit. Capture S1.
  4. process.continue → blocks until the next work_step hit.
     Capture S2.
  5. process.continue → blocks until the next hit. Capture S3.

Asserts:
  • All three snapshots match the slice-1c shape regex
    ^live:[0-9]+:[0-9a-f]{64}:[0-9a-f]{64}:[0-9a-f]{64}$.
  • <gen> strictly increases across the three (S1.gen < S2.gen < S3.gen).
  • <reg_digest> differs at S2 vs S1 (the loop index advanced — RIP /
    arg registers are different across hits).
  • <layout_digest> stays the same (no dlopen between hits).
  • <bp_digest> stays the same (the breakpoint is the same set).
  • bp_digest is the SAME well-known empty-set sentinel? NO — we
    have one bp installed, so it's the digest of one entry.
"""
import json
import os
import re
import subprocess
import sys


LIVE_RE = re.compile(r"^live:([0-9]+):([0-9a-f]{64}):([0-9a-f]{64}):([0-9a-f]{64})$")


def usage():
    sys.stderr.write(
        "usage: test_live_continue_provenance.py <ldbd> <looper>\n")
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
            raise RuntimeError(
                f"daemon closed stdout (stderr was: {err})")
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


def parse_live(snap):
    m = LIVE_RE.match(snap)
    if not m:
        return None
    return {
        "gen":    int(m.group(1)),
        "reg":    m.group(2),
        "layout": m.group(3),
        "bp":     m.group(4),
    }


def main():
    if len(sys.argv) != 3:
        usage()
    ldbd, looper = sys.argv[1], sys.argv[2]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n"); sys.exit(1)
    if not os.path.isfile(looper):
        sys.stderr.write(f"looper missing: {looper}\n"); sys.exit(1)

    failures = []

    def expect(cond, msg):
        if not cond:
            failures.append(msg)

    d = Daemon(ldbd)
    try:
        r = d.call("target.open", {"path": looper})
        expect(r["ok"], f"target.open: {r}")
        if not r["ok"]:
            raise RuntimeError("target.open failed")
        target_id = r["data"]["target_id"]

        # Set a probe (lldb_breakpoint, action=stop) on work_step.
        r = d.call("probe.create",
                   {"target_id": target_id,
                    "kind": "lldb_breakpoint",
                    "where": {"function": "work_step"},
                    "action": "stop"})
        expect(r["ok"], f"probe.create: {r}")
        if not r["ok"]:
            raise RuntimeError("probe.create failed")

        # Launch — runs to the first work_step hit and stops there.
        # NOTE: with stop_at_entry=True, the launch returns at the
        # entry point (gen=0). With stop_at_entry=False the launch
        # blocks and returns after the inferior hits the bp on
        # work_step (because the orchestrator returns true to LLDB
        # for action=stop).
        r = d.call("process.launch",
                   {"target_id": target_id, "stop_at_entry": False})
        expect(r["ok"], f"process.launch: {r}")
        if not r["ok"]:
            raise RuntimeError("launch failed")
        s1 = r["_provenance"]["snapshot"]
        p1 = parse_live(s1)
        expect(p1 is not None,
               f"S1 snapshot shape: {s1!r}")

        # Continue — blocks until the next bp hit.
        r = d.call("process.continue", {"target_id": target_id})
        expect(r["ok"], f"process.continue#1: {r}")
        if not r["ok"]:
            raise RuntimeError("continue#1 failed")
        s2 = r["_provenance"]["snapshot"]
        p2 = parse_live(s2)
        expect(p2 is not None, f"S2 snapshot shape: {s2!r}")

        # Continue — second round-trip.
        r = d.call("process.continue", {"target_id": target_id})
        expect(r["ok"], f"process.continue#2: {r}")
        if not r["ok"]:
            raise RuntimeError("continue#2 failed")
        s3 = r["_provenance"]["snapshot"]
        p3 = parse_live(s3)
        expect(p3 is not None, f"S3 snapshot shape: {s3!r}")

        # Cleanup.
        d.call("process.kill", {"target_id": target_id})

        if not (p1 and p2 and p3):
            for f in failures:
                sys.stderr.write(f"FAIL: {f}\n")
            sys.exit(1)

        # <gen> strictly increases across hits.
        expect(p1["gen"] < p2["gen"],
               f"<gen> didn't bump on continue#1: S1.gen={p1['gen']} "
               f"S2.gen={p2['gen']}")
        expect(p2["gen"] < p3["gen"],
               f"<gen> didn't bump on continue#2: S2.gen={p2['gen']} "
               f"S3.gen={p3['gen']}")

        # <reg_digest> differs across the round-trip — the loop index
        # advanced so the args + RIP are different on each hit.
        expect(p1["reg"] != p2["reg"],
               f"reg_digest unchanged across continue#1 — loop body "
               f"didn't advance? r1={p1['reg']} r2={p2['reg']}")
        expect(p2["reg"] != p3["reg"],
               f"reg_digest unchanged across continue#2: "
               f"r2={p2['reg']} r3={p3['reg']}")

        # <layout_digest> stays the same — no dlopen between hits.
        expect(p1["layout"] == p2["layout"],
               f"layout_digest drifted across continue#1: "
               f"l1={p1['layout']} l2={p2['layout']}")
        expect(p2["layout"] == p3["layout"],
               f"layout_digest drifted across continue#2")

        # <bp_digest> stays the same — same probe is installed.
        expect(p1["bp"] == p2["bp"] == p3["bp"],
               f"bp_digest drifted across continues: "
               f"{p1['bp']}, {p2['bp']}, {p3['bp']}")
    finally:
        d.close()

    if failures:
        for f in failures:
            sys.stderr.write(f"FAIL: {f}\n")
        sys.exit(1)
    print("process.continue round-trip provenance PASSED")


if __name__ == "__main__":
    main()
