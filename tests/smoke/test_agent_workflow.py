#!/usr/bin/env python3
"""Agent-style end-to-end workflow smoke for the V1 gate.

Exercises the minimum useful static RE path against the structs fixture:

  1. hello
  2. target.open
  3. session.create + session.attach
  4. module.list
  5. string.list
  6. string.xref
  7. disasm.function
  8. session.detach
  9. session.export
 10. fresh daemon + session.import

The point is not exact instruction text; it is that an agent can drive
the workflow, get the expected high-level shapes, and preserve the
transcript across a daemon restart.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile


def usage():
    sys.stderr.write("usage: test_agent_workflow.py <ldbd> <fixture>\n")
    sys.exit(2)


class Daemon:
    def __init__(self, ldbd, store_root):
        env = dict(os.environ)
        env["LDB_STORE_ROOT"] = store_root
        env.setdefault("LLDB_LOG_LEVEL", "error")
        self.proc = subprocess.Popen(
            [ldbd, "--stdio", "--log-level", "error"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True,
            bufsize=1,
        )
        self._next_id = 0

    def call(self, method, params=None):
        self._next_id += 1
        rid = f"r{self._next_id}"
        req = {
            "jsonrpc": "2.0",
            "id": rid,
            "method": method,
            "params": params or {},
        }
        self.proc.stdin.write(json.dumps(req) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            stderr = self.proc.stderr.read()
            raise RuntimeError(
                f"daemon closed stdout (stderr was: {stderr})"
            )
        return json.loads(line)

    def close(self):
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()


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

    src_root = tempfile.mkdtemp(prefix="ldb_smoke_agent_src_")
    dst_root = tempfile.mkdtemp(prefix="ldb_smoke_agent_dst_")
    pack_dir = tempfile.mkdtemp(prefix="ldb_smoke_agent_pack_")
    pack_path = os.path.join(pack_dir, "agent-workflow.ldbpack")

    failures = []

    def expect(cond, msg):
        if not cond:
            failures.append(msg)

    session_id = None
    expected_call_count = None
    expected_target_id = None

    try:
        d1 = Daemon(ldbd, src_root)
        try:
            hello = d1.call("hello")
            expect(hello.get("ok") is True, f"hello: {hello}")
            data = hello.get("data", {})
            expect(data.get("name") == "ldbd", f"hello name: {data}")
            expect("version" in data, f"hello version: {data}")
            expect(set(data.get("formats", [])) == {"json", "cbor"},
                   f"hello formats: {data}")

            opened = d1.call("target.open", {"path": fixture})
            expect(opened.get("ok") is True, f"target.open: {opened}")
            if opened.get("ok") is not True:
                raise RuntimeError("target.open failed")
            target_id = opened["data"]["target_id"]
            expected_target_id = str(target_id)

            created = d1.call("session.create", {
                "name": "agent_workflow",
                "target_id": expected_target_id,
            })
            expect(created.get("ok") is True, f"session.create: {created}")
            session_id = created.get("data", {}).get("id")
            expect(bool(session_id), f"session id missing: {created}")

            attached = d1.call("session.attach", {"id": session_id})
            expect(attached.get("ok") is True, f"session.attach: {attached}")

            modules = d1.call("module.list", {"target_id": target_id})
            expect(modules.get("ok") is True, f"module.list: {modules}")
            mod_list = modules.get("data", {}).get("modules", [])
            expect(len(mod_list) >= 1, f"module.list empty: {modules}")

            strings = d1.call("string.list", {
                "target_id": target_id,
                "min_len": 6,
            })
            expect(strings.get("ok") is True, f"string.list: {strings}")
            found_texts = {
                s.get("text")
                for s in strings.get("data", {}).get("strings", [])
            }
            expect("btp_schema.xml" in found_texts,
                   f"string.list missing btp_schema.xml: {strings}")
            expect("DXP/1.0" in found_texts,
                   f"string.list missing DXP/1.0: {strings}")

            xrefs = d1.call("string.xref", {
                "target_id": target_id,
                "text": "btp_schema.xml",
            })
            expect(xrefs.get("ok") is True, f"string.xref: {xrefs}")
            results = xrefs.get("data", {}).get("results", [])
            expect(len(results) >= 1, f"string.xref empty: {xrefs}")
            expect(any(
                xr.get("function") == "main"
                for r in results
                for xr in r.get("xrefs", [])
            ),
                   f"string.xref missing main attribution: {xrefs}")

            disasm = d1.call("disasm.function", {
                "target_id": target_id,
                "name": "point2_distance_sq",
            })
            expect(disasm.get("ok") is True, f"disasm.function: {disasm}")
            ddata = disasm.get("data", {})
            expect(ddata.get("found") is True, f"disasm miss: {disasm}")
            expect(len(ddata.get("instructions", [])) >= 1,
                   f"disasm instructions empty: {disasm}")

            detached = d1.call("session.detach")
            expect(detached.get("ok") is True, f"session.detach: {detached}")

            info = d1.call("session.info", {"id": session_id})
            expect(info.get("ok") is True, f"session.info: {info}")
            expected_call_count = info.get("data", {}).get("call_count")
            expect(isinstance(expected_call_count, int)
                   and expected_call_count >= 5,
                   f"session call_count too small: {info}")

            exported = d1.call("session.export", {
                "id": session_id,
                "path": pack_path,
            })
            expect(exported.get("ok") is True, f"session.export: {exported}")
            expect(os.path.isfile(pack_path), f"missing pack file: {pack_path}")
            manifest = exported.get("data", {}).get("manifest", {})
            expect(len(manifest.get("sessions", [])) == 1,
                   f"manifest sessions: {manifest}")
        finally:
            d1.close()

        d2 = Daemon(ldbd, dst_root)
        try:
            imported = d2.call("session.import", {"path": pack_path})
            expect(imported.get("ok") is True, f"session.import: {imported}")

            info2 = d2.call("session.info", {"id": session_id})
            expect(info2.get("ok") is True, f"imported session.info: {info2}")
            data2 = info2.get("data", {})
            expect(data2.get("name") == "agent_workflow",
                   f"imported session name: {data2}")
            expect(data2.get("call_count") == expected_call_count,
                   f"imported call_count drift: {data2}")
            expect(data2.get("target_id") == expected_target_id,
                   f"imported target_id drift: {data2}")
        finally:
            d2.close()

        if failures:
            for failure in failures:
                sys.stderr.write(f"FAIL: {failure}\n")
            sys.exit(1)
        print("agent workflow smoke test PASSED")
    finally:
        shutil.rmtree(src_root, ignore_errors=True)
        shutil.rmtree(dst_root, ignore_errors=True)
        shutil.rmtree(pack_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
