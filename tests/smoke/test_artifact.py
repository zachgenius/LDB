#!/usr/bin/env python3
"""Smoke test for artifact.put / artifact.get / artifact.list / artifact.tag.

Drives the full RPC surface end-to-end: round-trip a blob, list with
filters, fetch with a max_bytes preview, tag and re-list. Uses
LDB_STORE_ROOT pointed at a per-test tmpdir — never touches ~/.ldb.
"""
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile


def usage():
    sys.stderr.write("usage: test_artifact.py <ldbd>\n")
    sys.exit(2)


def main():
    if len(sys.argv) != 2:
        usage()
    ldbd = sys.argv[1]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n"); sys.exit(1)

    # Per-run tmpdir for the store root. mkdtemp() is unique per call,
    # cleaned up in the finally below. Tests must not touch ~/.ldb.
    store_root = tempfile.mkdtemp(prefix="ldb_smoke_artifact_")

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
            # describe.endpoints must list the four artifact.* methods.
            r0 = call("describe.endpoints")
            expect(r0["ok"], f"describe.endpoints: {r0}")
            methods = {e["method"] for e in r0["data"]["endpoints"]}
            for m in ("artifact.put", "artifact.get",
                      "artifact.list", "artifact.tag"):
                expect(m in methods, f"missing endpoint: {m}")

            # --- put ----------------------------------------------------
            payload1 = b"<schema name=\"btp\"><frame size=\"512\"/></schema>"
            payload2 = b"\x00\x01\x02\x03\x04PADDING-BLOB" + bytes(200)

            r1 = call("artifact.put", {
                "build_id": "build-deadbeef",
                "name": "btp_schema.xml",
                "bytes_b64": base64.b64encode(payload1).decode(),
                "format": "xml",
                "meta": {"captured_at": "2026-05-05", "hit": 1},
            })
            expect(r1["ok"], f"artifact.put #1: {r1}")
            id1 = r1["data"]["id"]
            expect(id1 > 0, f"bad id: {id1}")
            expect(r1["data"]["sha256"] == hashlib.sha256(payload1).hexdigest(),
                   f"sha256 mismatch: {r1['data']['sha256']}")
            expect(r1["data"]["byte_size"] == len(payload1),
                   f"byte_size: {r1['data']['byte_size']}")
            expect(os.path.isfile(r1["data"]["stored_path"]),
                   f"blob file missing: {r1['data']['stored_path']}")

            # Different artifact, same build.
            r2 = call("artifact.put", {
                "build_id": "build-deadbeef",
                "name": "frame.bin",
                "bytes_b64": base64.b64encode(payload2).decode(),
            })
            expect(r2["ok"], f"artifact.put #2: {r2}")

            # Different build entirely.
            r3 = call("artifact.put", {
                "build_id": "build-feedface",
                "name": "schema_other.xml",
                "bytes_b64": base64.b64encode(b"other").decode(),
                "format": "xml",
            })
            expect(r3["ok"], f"artifact.put #3: {r3}")

            # --- list ---------------------------------------------------
            rl_all = call("artifact.list", {})
            expect(rl_all["ok"], f"artifact.list all: {rl_all}")
            expect(rl_all["data"]["total"] == 3,
                   f"expected 3 artifacts, got {rl_all['data']['total']}")

            rl_b = call("artifact.list", {"build_id": "build-deadbeef"})
            expect(rl_b["ok"] and rl_b["data"]["total"] == 2,
                   f"build_id filter: {rl_b}")

            # name_pattern uses LIKE — '%' is wildcard.
            rl_xml = call("artifact.list", {"name_pattern": "%.xml"})
            expect(rl_xml["ok"] and rl_xml["data"]["total"] == 2,
                   f"name_pattern: {rl_xml}")
            for a in rl_xml["data"]["artifacts"]:
                expect(a["name"].endswith(".xml"),
                       f"non-xml in pattern result: {a}")
                expect("bytes_b64" not in a,
                       f"list shouldn't carry bytes: {a}")

            # --- get by name -------------------------------------------
            rg = call("artifact.get",
                      {"build_id": "build-deadbeef", "name": "btp_schema.xml"})
            expect(rg["ok"], f"artifact.get: {rg}")
            got = base64.b64decode(rg["data"]["bytes_b64"])
            expect(got == payload1, f"payload mismatch (len={len(got)})")
            expect(rg["data"]["sha256"] ==
                   hashlib.sha256(payload1).hexdigest(),
                   f"sha mismatch on get: {rg['data']['sha256']}")
            expect(rg["data"]["format"] == "xml",
                   f"format: {rg['data']}")
            expect(rg["data"]["meta"]["hit"] == 1,
                   f"meta: {rg['data']}")
            expect(rg["data"]["truncated"] is False,
                   f"unexpected truncated: {rg['data']}")

            # --- get with view.max_bytes preview -----------------------
            rgv = call("artifact.get",
                       {"build_id": "build-deadbeef", "name": "frame.bin",
                        "view": {"max_bytes": 8}})
            expect(rgv["ok"], f"artifact.get view: {rgv}")
            preview = base64.b64decode(rgv["data"]["bytes_b64"])
            expect(len(preview) == 8, f"preview length: {len(preview)}")
            expect(preview == payload2[:8],
                   f"preview content: {preview!r}")
            expect(rgv["data"]["truncated"] is True,
                   f"expected truncated=True: {rgv['data']}")
            expect(rgv["data"]["byte_size"] == len(payload2),
                   f"byte_size should be full: {rgv['data']['byte_size']}")

            # --- get by id ---------------------------------------------
            rgid = call("artifact.get", {"id": id1})
            expect(rgid["ok"] and
                   base64.b64decode(rgid["data"]["bytes_b64"]) == payload1,
                   f"get by id: {rgid}")

            # --- tag ----------------------------------------------------
            rt1 = call("artifact.tag",
                       {"id": id1, "tags": ["captured", "schema"]})
            expect(rt1["ok"], f"artifact.tag #1: {rt1}")
            expect(set(rt1["data"]["tags"]) == {"captured", "schema"},
                   f"tags: {rt1}")

            # Idempotent + additive.
            rt2 = call("artifact.tag",
                       {"id": id1, "tags": ["schema", "v1"]})
            expect(rt2["ok"], f"artifact.tag #2: {rt2}")
            expect(set(rt2["data"]["tags"]) == {"captured", "schema", "v1"},
                   f"tags additive: {rt2}")

            # list now reflects tags.
            rl_after = call("artifact.list",
                            {"build_id": "build-deadbeef",
                             "name_pattern": "btp_%"})
            expect(rl_after["ok"], f"artifact.list post-tag: {rl_after}")
            arts = rl_after["data"]["artifacts"]
            expect(len(arts) == 1, f"post-tag count: {arts}")
            expect(set(arts[0]["tags"]) == {"captured", "schema", "v1"},
                   f"list tags reflect: {arts[0]}")

            # --- error paths -------------------------------------------
            # Missing required field.
            re1 = call("artifact.put",
                       {"build_id": "b", "name": "n"})
            expect(not re1["ok"] and
                   re1.get("error", {}).get("code") == -32602,
                   f"missing bytes_b64: {re1}")

            # Bad base64.
            re2 = call("artifact.put",
                       {"build_id": "b", "name": "n",
                        "bytes_b64": "not!base64!"})
            expect(not re2["ok"] and
                   re2.get("error", {}).get("code") == -32602,
                   f"bad b64: {re2}")

            # Bogus id.
            re3 = call("artifact.get", {"id": 999999})
            expect(not re3["ok"] and
                   re3.get("error", {}).get("code") == -32000,
                   f"bogus id: {re3}")

            # Tag missing artifact.
            re4 = call("artifact.tag",
                       {"id": 999999, "tags": ["x"]})
            expect(not re4["ok"] and
                   re4.get("error", {}).get("code") == -32000,
                   f"tag missing: {re4}")

            # --- replace contract --------------------------------------
            replacement = b"REPLACED PAYLOAD"
            rr = call("artifact.put", {
                "build_id": "build-deadbeef",
                "name": "btp_schema.xml",
                "bytes_b64": base64.b64encode(replacement).decode(),
            })
            expect(rr["ok"], f"replace put: {rr}")
            expect(rr["data"]["id"] != id1,
                   f"replace should change id: {rr['data']['id']} vs {id1}")

            rr_get = call("artifact.get",
                          {"build_id": "build-deadbeef",
                           "name": "btp_schema.xml"})
            expect(rr_get["ok"], f"replace get: {rr_get}")
            expect(base64.b64decode(rr_get["data"]["bytes_b64"]) == replacement,
                   "replace payload mismatch")

            # Total still 3 (replace, not insert).
            rl_post = call("artifact.list", {})
            expect(rl_post["data"]["total"] == 3,
                   f"replace shouldn't grow total: {rl_post['data']}")
        finally:
            try:
                proc.stdin.close()
            except Exception:
                pass
            proc.wait(timeout=10)

        if failures:
            for f in failures:
                sys.stderr.write(f"FAIL: {f}\n")
            sys.exit(1)
        print("artifact smoke test PASSED")
    finally:
        # Defensive: never leak the tmpdir even on test failure.
        shutil.rmtree(store_root, ignore_errors=True)


if __name__ == "__main__":
    main()
