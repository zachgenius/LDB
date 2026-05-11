#!/usr/bin/env python3
"""Cross-backend smoke for ldbd --backend=gdb (post-V1 plan #8).

SKIP if gdb is not on PATH. Otherwise exercises the GdbMiBackend's
v1.4 implemented surface end-to-end through ldbd:

  - hello surfaces capabilities.backend == "gdb"
  - target.open + module.list + symbol.find + disasm.range work
    end-to-end against the structs fixture
  - methods that haven't been ported yet (process.launch,
    type.layout, ...) return a clean -32000 with "not implemented
    yet" rather than crashing
  - target.close cleans up

The goal is abstraction validation: every assertion below should
also hold under --backend=lldb (run the same script with the env
toggle to verify); divergence reveals where DebuggerBackend's
contract leaks LLDB-isms. See docs/18-gdbmi-backend.md.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile


def usage():
    sys.stderr.write("usage: test_gdbmi_backend.py <ldbd> <fixture>\n")
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
    if not shutil.which("gdb"):
        print("gdbmi_backend smoke: gdb not on PATH; SKIPPING")
        return

    store_root = tempfile.mkdtemp(prefix="ldb_smoke_gdbmi_")
    env = dict(os.environ)
    env["LDB_STORE_ROOT"] = store_root
    env.setdefault("LLDB_LOG_LEVEL", "error")

    proc = subprocess.Popen(
        [ldbd, "--stdio", "--log-level", "error", "--backend", "gdb"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
        bufsize=1,
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
        # hello surfaces the active backend.
        r = call("hello")
        expect(r["ok"], f"hello: {r}")
        caps = r["data"].get("capabilities", {})
        expect(caps.get("backend") == "gdb",
               f"capabilities.backend should be 'gdb': {caps}")

        # target.open against the structs fixture.
        ropen = call("target.open", {"path": fixture})
        expect(ropen["ok"], f"target.open: {ropen}")
        target_id = ropen["data"]["target_id"]
        expect(target_id != 0, f"target_id: {ropen}")

        # module.list returns the main exec (no shared libs in v1.4
        # static targets — documented in docs/18).
        rmods = call("module.list", {"target_id": target_id})
        expect(rmods["ok"], f"module.list: {rmods}")
        mods = rmods["data"]["modules"]
        expect(len(mods) == 1, f"expected 1 module, got {len(mods)}: {mods}")
        expect(mods[0]["path"] == fixture,
               f"module path: {mods[0]}")

        # symbol.find by exact name returns the function with a
        # resolved address.
        rsym = call("symbol.find", {
            "target_id": target_id,
            "name": "point2_distance_sq",
            "kind": "function",
        })
        expect(rsym["ok"], f"symbol.find: {rsym}")
        matches = rsym["data"]["matches"]
        found = False
        for m in matches:
            if m.get("name") == "point2_distance_sq":
                # The dispatcher emits the symbol's file address as
                # `addr` (see symbol_match_to_json); `address` is the
                # disasm-instruction field name. Accept either to be
                # robust to a future rename.
                addr = m.get("addr") or m.get("address") or 0
                expect(addr != 0,
                       f"address resolution: {m}")
                found = True
        expect(found, f"point2_distance_sq not in matches: {matches}")

        # disasm.function on a known small function.
        rdis = call("disasm.function", {
            "target_id": target_id,
            "name": "point2_distance_sq",
        })
        expect(rdis["ok"], f"disasm.function: {rdis}")
        if rdis["ok"]:
            insns = rdis["data"].get("instructions", [])
            expect(len(insns) >= 4,
                   f"too few insns: {len(insns)}")

        # Methods not yet ported to GdbMiBackend surface a clean
        # typed error rather than crashing. Confirming a few
        # representatives that are still stubbed (per docs/18):
        for method, params in [
            ("type.layout", {"target_id": target_id, "name": "point2"}),
            ("mem.regions", {"target_id": target_id}),
        ]:
            r_unimpl = call(method, params)
            expect(not r_unimpl["ok"],
                   f"{method} should still fail in v1.4 gdb backend: "
                   f"{r_unimpl}")
            err = r_unimpl.get("error", {})
            msg = err.get("message", "")
            expect("not implemented yet" in msg or
                   err.get("code") in (-32000, -32002, -32003),
                   f"{method} should return typed error: {r_unimpl}")

        # Clean target close.
        rcls = call("target.close", {"target_id": target_id})
        expect(rcls["ok"], f"target.close: {rcls}")
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        proc.wait(timeout=10)
        shutil.rmtree(store_root, ignore_errors=True)

    if failures:
        for f in failures:
            sys.stderr.write(f"FAIL: {f}\n")
        sys.exit(1)
    print("gdbmi_backend smoke test PASSED")


if __name__ == "__main__":
    main()
