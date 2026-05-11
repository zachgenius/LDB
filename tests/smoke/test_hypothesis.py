#!/usr/bin/env python3
"""Smoke test for hypothesis-v1 artifact type (post-V1 plan #6).

Covers:
  * artifact.hypothesis_template returns a JSON envelope that itself
    validates.
  * artifact.put with format=hypothesis-v1 and a valid envelope round-
    trips through artifact.get verbatim.
  * artifact.put with format=hypothesis-v1 and an invalid envelope
    (each independent error path) returns -32602 with a message naming
    the offending field.
  * artifact.put without hypothesis-v1 format remains a free-for-all
    (no validation regressions on existing flows).
  * describe.endpoints registers artifact.hypothesis_template.
"""
import base64
import json
import os
import subprocess
import sys
import tempfile


def usage():
    sys.stderr.write("usage: test_hypothesis.py <ldbd>\n")
    sys.exit(2)


def b64(obj):
    return base64.b64encode(json.dumps(obj).encode("utf-8")).decode("ascii")


def main():
    if len(sys.argv) != 2:
        usage()
    ldbd = sys.argv[1]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n")
        sys.exit(1)

    store_root = tempfile.mkdtemp(prefix="ldb_smoke_hypothesis_")
    env = dict(os.environ)
    env["LDB_STORE_ROOT"] = store_root
    env.setdefault("LLDB_LOG_LEVEL", "error")

    proc = subprocess.Popen(
        [ldbd, "--stdio", "--log-level", "error"],
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
        # Schema: artifact.hypothesis_template is in describe.endpoints.
        desc = call("describe.endpoints", {})
        expect(desc["ok"], f"describe.endpoints: {desc}")
        methods = {e["method"] for e in desc["data"]["endpoints"]}
        expect("artifact.hypothesis_template" in methods,
               "artifact.hypothesis_template missing from describe")

        # Template returns a validating envelope.
        tmpl = call("artifact.hypothesis_template", {})
        expect(tmpl["ok"], f"hypothesis_template: {tmpl}")
        template = tmpl["data"]["template"]
        for required in ("confidence", "evidence_refs"):
            expect(required in template,
                   f"template missing {required}: {template}")

        # Put the template verbatim — must succeed.
        put_tmpl = call("artifact.put", {
            "build_id": "investigation-1",
            "name":     "hypothesis:initial",
            "bytes_b64": b64(template),
            "format":   "hypothesis-v1",
        })
        expect(put_tmpl["ok"], f"put template: {put_tmpl}")

        # Put a richer hypothesis envelope.
        good = {
            "confidence": 0.72,
            "evidence_refs": [1, 2, 3],
            "statement": "the parser drops UDP packets > 256 bytes",
            "rationale": "see disasm at btp_parse+0x140",
        }
        put_good = call("artifact.put", {
            "build_id": "investigation-1",
            "name":     "hypothesis:packet-size",
            "bytes_b64": b64(good),
            "format":   "hypothesis-v1",
        })
        expect(put_good["ok"], f"put good: {put_good}")
        good_id = put_good["data"]["id"]

        # Round-trip via artifact.get.
        got = call("artifact.get", {"id": good_id})
        expect(got["ok"], f"get: {got}")
        round_trip = json.loads(base64.b64decode(got["data"]["bytes_b64"]))
        expect(round_trip == good,
               f"round-trip mismatch: got {round_trip}")
        expect(got["data"]["format"] == "hypothesis-v1",
               f"format mismatch: {got}")

        # Negative paths — each should be -32602.
        bad_cases = [
            ({"evidence_refs": []},
             "confidence", "missing confidence"),
            ({"confidence": "high", "evidence_refs": []},
             "confidence", "confidence wrong type"),
            ({"confidence": 1.1, "evidence_refs": []},
             "confidence", "confidence out of range"),
            ({"confidence": 0.5},
             "evidence_refs", "missing evidence_refs"),
            ({"confidence": 0.5, "evidence_refs": "1,2,3"},
             "evidence_refs", "evidence_refs wrong type"),
            ({"confidence": 0.5, "evidence_refs": ["one", "two"]},
             "evidence_refs", "evidence_refs items wrong type"),
        ]
        for body, expected_word, label in bad_cases:
            r = call("artifact.put", {
                "build_id": "investigation-1",
                "name":     f"hypothesis:bad-{label}",
                "bytes_b64": b64(body),
                "format":   "hypothesis-v1",
            })
            expect(not r["ok"], f"{label}: should have failed: {r}")
            expect(r.get("error", {}).get("code") == -32602,
                   f"{label}: expected -32602, got {r}")
            msg = r.get("error", {}).get("message", "")
            expect(expected_word in msg,
                   f"{label}: error '{msg}' should mention "
                   f"'{expected_word}'")

        # Non-JSON bytes for hypothesis-v1 → -32602.
        not_json = call("artifact.put", {
            "build_id": "investigation-1",
            "name":     "hypothesis:not-json",
            "bytes_b64": base64.b64encode(b"not json at all").decode("ascii"),
            "format":   "hypothesis-v1",
        })
        expect(not not_json["ok"] and
               not_json.get("error", {}).get("code") == -32602,
               f"not-json hypothesis expected -32602, got {not_json}")

        # Regression check: artifact.put without hypothesis-v1 format
        # remains unconstrained (raw bytes accepted).
        raw = call("artifact.put", {
            "build_id": "investigation-1",
            "name":     "log:raw",
            "bytes_b64": base64.b64encode(b"\x00\x01\x02 raw bytes").decode("ascii"),
        })
        expect(raw["ok"], f"raw artifact.put broken: {raw}")
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
    print("hypothesis smoke test PASSED")


if __name__ == "__main__":
    main()
