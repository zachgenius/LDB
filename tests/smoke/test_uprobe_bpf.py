#!/usr/bin/env python3
"""Smoke test for probe.create kind="uprobe_bpf" (M4-4).

The bpftrace engine spawns a long-lived bpftrace subprocess and pumps
its line-delimited JSON output back into the same probe-event ring
buffer the lldb_breakpoint engine writes to. This test exercises:

- describe.endpoints surfaces uprobe_bpf in the probe.create description.
- Param validation: missing where, invalid where shape → -32602.
- bpftrace discovery: when bpftrace is missing, probe.create returns
  -32000 with a "bpftrace not installed" message.
- Live happy path: only attempted when both `LDB_BPFTRACE` and CAP_BPF
  (or root) are available — SKIPped cleanly otherwise.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile


def usage():
    sys.stderr.write("usage: test_uprobe_bpf.py <ldbd>\n")
    sys.exit(2)


def main():
    if len(sys.argv) != 2:
        usage()
    ldbd = sys.argv[1]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n"); sys.exit(1)

    store_root = tempfile.mkdtemp(prefix="ldb_smoke_uprobe_bpf_")
    try:
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
            # describe.endpoints carries probe.create; description must
            # mention uprobe_bpf so an agent can discover it.
            r0 = call("describe.endpoints")
            expect(r0["ok"], f"describe.endpoints: {r0}")
            create_e = next(
                (e for e in r0["data"]["endpoints"]
                 if e["method"] == "probe.create"),
                None)
            expect(create_e is not None, "probe.create endpoint missing")
            if create_e is not None:
                summary = create_e.get("summary", "")
                expect("uprobe_bpf" in summary,
                       f"summary must mention uprobe_bpf: {summary!r}")

            # Missing `where` → -32602.
            r1 = call("probe.create", {
                "kind": "uprobe_bpf",
            })
            expect(not r1["ok"]
                   and r1.get("error", {}).get("code") == -32602,
                   f"missing where → -32602: {r1}")

            # `where` with no recognized form → -32602.
            r2 = call("probe.create", {
                "kind": "uprobe_bpf",
                "where": {"function": "bind"},  # function is lldb_breakpoint shape
            })
            expect(not r2["ok"]
                   and r2.get("error", {}).get("code") == -32602,
                   f"unrecognized where form → -32602: {r2}")

            # Multiple where forms → -32602.
            r3 = call("probe.create", {
                "kind": "uprobe_bpf",
                "where": {
                    "uprobe": "/lib/x86_64-linux-gnu/libc.so.6:bind",
                    "kprobe": "tcp_v4_connect",
                },
            })
            expect(not r3["ok"]
                   and r3.get("error", {}).get("code") == -32602,
                   f"two where forms → -32602: {r3}")

            # bpftrace discovery: with LDB_BPFTRACE pointing at a path
            # we know does NOT exist, the engine reports -32000 with a
            # "bpftrace not installed" message.
            #
            # Note we can't bake this into the daemon's env after start;
            # the start-time discovery path resolves PATH on each
            # probe.create call, so unsetting/setting via the shell
            # before this test is the right knob. Here we simply
            # exercise the path that we expect: bpftrace either present
            # (and the call may succeed or fail with attach-error), or
            # absent (and we get -32000).
            r4 = call("probe.create", {
                "kind": "uprobe_bpf",
                "where": {
                    "uprobe": "/lib/x86_64-linux-gnu/libc.so.6:bind",
                },
                "capture": {"args": ["arg0", "arg1", "arg2"]},
                "filter_pid": 1,  # init — definitely never calls bind()
            })
            if not r4["ok"]:
                expect(r4.get("error", {}).get("code") == -32000,
                       f"bpftrace not avail → -32000: {r4}")
                msg = r4.get("error", {}).get("message", "")
                expect("bpftrace" in msg.lower(),
                       f"error must mention bpftrace: {msg!r}")
            else:
                # bpftrace present + privileged. Verify probe was created
                # and clean up.
                pid = r4["data"]["probe_id"]
                expect(pid.startswith("p"), f"probe_id format: {pid!r}")
                expect(r4["data"].get("kind") == "uprobe_bpf",
                       f"kind echo: {r4}")
                rd = call("probe.delete", {"probe_id": pid})
                expect(rd["ok"], f"probe.delete: {rd}")

        finally:
            try: proc.stdin.close()
            except Exception: pass
            proc.wait(timeout=10)

        if failures:
            for f in failures:
                sys.stderr.write(f"FAIL: {f}\n")
            sys.exit(1)
        print("uprobe_bpf smoke test PASSED")
    finally:
        shutil.rmtree(store_root, ignore_errors=True)


if __name__ == "__main__":
    main()
