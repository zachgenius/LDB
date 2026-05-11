#!/usr/bin/env python3
"""Smoke test for view.diff_against on module.list (post-V1 plan #5).

The diff machinery is most useful on live targets where snapshots change
across calls. Strategy:

  1. Open a fixture binary statically (no live process) — first
     module.list call captures the static-only baseline snapshot.
  2. Launch the process stopped at entry — snapshot now reflects the
     loaded shared libraries / dyld setup, so the module set is
     materially larger.
  3. Call module.list with view.diff_against=<first_snapshot>.
     Expect the response to contain only "added" entries (new libs),
     each with diff_op="added".
  4. Negative path: call again with a bogus diff_against → the daemon
     surfaces diff_baseline_missing=true and the full module array.
  5. Call module.list with diff_against=<current snapshot> (no change
     between cache and now) → empty diff array.
"""
import json
import os
import subprocess
import sys
import tempfile


def usage():
    sys.stderr.write("usage: test_view_diff.py <ldbd> <fixture>\n")
    sys.exit(2)


def main():
    if len(sys.argv) != 3:
        usage()
    ldbd, fixture = sys.argv[1:3]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n")
        sys.exit(1)
    if not os.path.isfile(fixture):
        sys.stderr.write(f"fixture missing: {fixture}\n")
        sys.exit(1)

    store_root = tempfile.mkdtemp(prefix="ldb_smoke_view_diff_")
    env = dict(os.environ)
    env["LDB_STORE_ROOT"] = store_root
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
            sys.stderr.write(f"daemon closed stdout (stderr: {stderr})\n")
            sys.exit(1)
        return json.loads(line)

    failures = []

    def expect(cond, msg):
        if not cond:
            failures.append(msg)

    try:
        opened = call("target.open", {"path": fixture})
        expect(opened["ok"], f"target.open: {opened}")
        target_id = opened["data"]["target_id"]

        # Step 1: static module.list — capture baseline snapshot.
        r1 = call("module.list", {"target_id": target_id})
        expect(r1["ok"], f"module.list (static): {r1}")
        static_snapshot = r1.get("_provenance", {}).get("snapshot", "")
        expect(bool(static_snapshot),
               f"static snapshot missing: {r1.get('_provenance')}")
        static_module_count = len(r1["data"]["modules"])

        # Step 2: launch stopped-at-entry. On Linux this typically
        # ADDS modules (ld.so + libc + libpthread map into the address
        # space). On macOS the launch step often REDUCES the
        # module.list output to just dyld + the binary, because LLDB
        # discards the pre-resolved LC_LOAD_DYLIB entries it had
        # enumerated at target.open and re-derives the actually-loaded
        # set from the live process. The diff machinery doesn't care
        # which direction the set moved; it only needs the snapshots
        # to differ and the diff to contain *some* annotated entries.
        launched = call("process.launch", {
            "target_id": target_id,
            "stop_at_entry": True,
        })
        expect(launched["ok"], f"process.launch: {launched}")

        r2 = call("module.list", {"target_id": target_id})
        expect(r2["ok"], f"module.list (post-launch): {r2}")
        live_snapshot = r2.get("_provenance", {}).get("snapshot", "")
        expect(live_snapshot != static_snapshot,
               f"snapshots should differ: static={static_snapshot} "
               f"live={live_snapshot}")
        live_module_count = len(r2["data"]["modules"])
        expect(live_module_count != static_module_count,
               f"module set should change across launch on every "
               f"supported platform: {static_module_count} -> "
               f"{live_module_count}")

        # Step 3: diff against the static snapshot. Direction-agnostic:
        # we only require that the diff contains SOME annotated entries
        # and that each carries a valid diff_op. macOS may produce only
        # "removed" entries (dyld discarded the pre-resolved list);
        # Linux typically produces only "added" entries (loader filled
        # in the dependency closure).
        r3 = call("module.list", {
            "target_id": target_id,
            "view": {"diff_against": static_snapshot},
        })
        expect(r3["ok"], f"module.list diff: {r3}")
        data3 = r3["data"]
        expect(data3.get("diff_against") == static_snapshot,
               f"diff_against echo missing: {data3}")
        expect(data3.get("diff_baseline_missing") is False,
               f"baseline should be cached: {data3}")
        diff_items = data3["modules"]
        for it in diff_items:
            op = it.get("diff_op")
            expect(op in ("added", "removed"),
                   f"unexpected diff_op: {it}")
        expect(len(diff_items) >= 1,
               f"expected at least one annotated entry in the diff "
               f"(snapshots differed, so the diff must be non-empty): "
               f"{diff_items}")

        # Step 4: bogus diff_against → baseline missing flag.
        r4 = call("module.list", {
            "target_id": target_id,
            "view": {"diff_against": "core:0000000000000000"},
        })
        expect(r4["ok"], f"module.list bogus diff: {r4}")
        expect(r4["data"].get("diff_baseline_missing") is True,
               f"expected diff_baseline_missing=true: {r4['data']}")
        expect(len(r4["data"]["modules"]) == live_module_count,
               f"baseline-miss should return full array: {r4['data']}")

        # Step 5: diff against current snapshot — empty diff.
        # The previous call (r4) recached at live_snapshot; we expect
        # the diff against live_snapshot to be empty.
        r5 = call("module.list", {
            "target_id": target_id,
            "view": {"diff_against": live_snapshot},
        })
        expect(r5["ok"], f"module.list self-diff: {r5}")
        expect(r5["data"].get("diff_baseline_missing") is False,
               f"self-diff baseline should be cached: {r5['data']}")
        expect(len(r5["data"]["modules"]) == 0,
               f"self-diff should be empty: {r5['data']}")

        # Schema: describe.endpoints mentions diff_against on module.list.
        desc = call("describe.endpoints", {})
        for e in desc["data"]["endpoints"]:
            if e["method"] == "module.list":
                expect("diff_against" in e["summary"],
                       f"module.list summary lacks diff_against: "
                       f"{e['summary']}")

        call("process.kill", {"target_id": target_id})
        call("target.close", {"target_id": target_id})
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        proc.wait(timeout=10)
        import shutil
        shutil.rmtree(store_root, ignore_errors=True)

    if failures:
        for f in failures:
            sys.stderr.write(f"FAIL: {f}\n")
        sys.exit(1)
    print("view_diff smoke test PASSED")


if __name__ == "__main__":
    main()
