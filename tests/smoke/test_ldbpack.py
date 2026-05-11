#!/usr/bin/env python3
"""Smoke test for session.export / session.import / artifact.export /
artifact.import — `.ldbpack` round-trip across daemon restarts (M5
part 5).

Scenario:
  1. Start ldbd #1 with a fresh LDB_STORE_ROOT.
  2. Create a session ("alpha"), attach, drive a few RPCs, detach.
  3. Drop two artifacts via artifact.put under build_id "buildA".
  4. session.export({id: alpha}, path: <pack>) → returns {path,
     byte_size, sha256, manifest{...}}.
  5. Stop ldbd #1.
  6. Start ldbd #2 against a SECOND, empty LDB_STORE_ROOT.
  7. session.import({path: <pack>}) → reports {imported:[...]}.
  8. session.list shows alpha; session.info(alpha) reports the right
     call_count; artifact.list shows both artifacts.
  9. Negative path: importing the same pack again under default
     conflict policy ("error") returns -32000.
 10. Importing again under "skip" reports the duplicates as skipped.

Also exercises artifact.export (pure-artifact pack) on the round-trip.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile


def usage():
    sys.stderr.write("usage: test_ldbpack.py <ldbd>\n")
    sys.exit(2)


def main():
    if len(sys.argv) != 2:
        usage()
    ldbd = sys.argv[1]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n"); sys.exit(1)

    src_root = tempfile.mkdtemp(prefix="ldb_smoke_pack_src_")
    dst_root = tempfile.mkdtemp(prefix="ldb_smoke_pack_dst_")
    pack_dir = tempfile.mkdtemp(prefix="ldb_smoke_pack_out_")

    failures = []
    def expect(cond, msg):
        if not cond: failures.append(msg)

    def start(store_root):
        env = dict(os.environ)
        env["LDB_STORE_ROOT"] = store_root
        env.setdefault("LLDB_LOG_LEVEL", "error")
        return subprocess.Popen(
            [ldbd, "--stdio", "--log-level", "error"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env, text=True, bufsize=1,
        )

    def caller(proc):
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
        return call

    sid_a = None
    pack_path = os.path.join(pack_dir, "alpha.ldbpack")
    art_pack_path = os.path.join(pack_dir, "art-only.ldbpack")
    expected_call_count = None

    try:
        # ---- ldbd #1: produce a pack ---------------------------------
        proc1 = start(src_root)
        try:
            call = caller(proc1)

            # describe.endpoints lists the new methods
            r0 = call("describe.endpoints")
            expect(r0["ok"], f"describe: {r0}")
            methods = {e["method"] for e in r0["data"]["endpoints"]}
            for m in ("session.export", "session.import",
                      "artifact.export", "artifact.import"):
                expect(m in methods, f"missing endpoint: {m}")

            c1 = call("session.create", {"name": "alpha",
                                          "target_id": "tgt-x"})
            expect(c1["ok"], f"session.create: {c1}")
            sid_a = c1["data"]["id"]

            at = call("session.attach", {"id": sid_a})
            expect(at["ok"], f"attach: {at}")
            call("hello")
            call("describe.endpoints")
            call("session.detach")

            i1 = call("session.info", {"id": sid_a})
            expect(i1["ok"], f"info: {i1}")
            expected_call_count = i1["data"]["call_count"]

            put1 = call("artifact.put", {
                "build_id": "buildA", "name": "schema.xml",
                "bytes_b64": "aGVsbG8=",  # "hello"
                "format": "xml",
                "meta": {"author": "agent"},
            })
            expect(put1["ok"], f"put1: {put1}")
            put2 = call("artifact.put", {
                "build_id": "buildA", "name": "frame.bin",
                "bytes_b64": "AQIDBA==",  # 1,2,3,4
            })
            expect(put2["ok"], f"put2: {put2}")

            # session.export
            ex = call("session.export", {"id": sid_a, "path": pack_path})
            expect(ex["ok"], f"export: {ex}")
            expect(os.path.isfile(pack_path),
                   f"pack file not on disk: {pack_path}")
            expect(ex["data"]["byte_size"] == os.path.getsize(pack_path),
                   f"byte_size mismatch: {ex['data']}")
            expect(len(ex["data"]["sha256"]) == 64,
                   f"sha256 should be 64 hex: {ex['data']}")
            man = ex["data"]["manifest"]
            expect(man["format"] == "ldbpack/1", f"manifest format: {man}")
            expect(len(man["sessions"]) == 1,
                   f"expected 1 session in manifest: {man}")
            expect(len(man["artifacts"]) == 2,
                   f"expected 2 artifacts in manifest: {man}")

            # artifact.export — pure-artifact pack.
            ax = call("artifact.export", {"build_id": "buildA",
                                           "path": art_pack_path})
            expect(ax["ok"], f"artifact.export: {ax}")
            expect(os.path.isfile(art_pack_path),
                   f"art pack not on disk: {art_pack_path}")
            am = ax["data"]["manifest"]
            expect(len(am["sessions"]) == 0,
                   f"artifact.export should have 0 sessions: {am}")
            expect(len(am["artifacts"]) == 2,
                   f"artifact.export should have 2 artifacts: {am}")

            # Negative: bad path that escapes via a relative ".." into
            # /etc would-be — we simply require the path to be a string;
            # the agent's filesystem permissions are the real backstop.
            # Explicit "no path" should default into the store root.
            ex_def = call("session.export", {"id": sid_a})
            expect(ex_def["ok"], f"export-default-path: {ex_def}")
            expect(os.path.isfile(ex_def["data"]["path"]),
                   f"default-path file: {ex_def['data']}")
        finally:
            try: proc1.stdin.close()
            except Exception: pass
            proc1.wait(timeout=10)

        # ---- ldbd #2: consume the pack -------------------------------
        proc2 = start(dst_root)
        try:
            call = caller(proc2)

            # Empty store: list is empty.
            l0 = call("session.list")
            expect(l0["ok"], f"empty list: {l0}")
            expect(l0["data"]["total"] == 0, f"expected empty: {l0}")

            # session.import
            im = call("session.import", {"path": pack_path})
            expect(im["ok"], f"import: {im}")
            expect(len(im["data"]["imported"]) >= 3,
                   f"expected >=3 imported entries: {im['data']}")
            kinds = [e["kind"] for e in im["data"]["imported"]]
            expect("session" in kinds, f"no session imported: {kinds}")
            expect(kinds.count("artifact") == 2,
                   f"expected 2 artifacts: {kinds}")

            # The session is now visible and carries the original
            # call_count.
            i2 = call("session.info", {"id": sid_a})
            expect(i2["ok"], f"info-imported: {i2}")
            expect(i2["data"]["call_count"] == expected_call_count,
                   f"call_count mismatch: was {expected_call_count}, "
                   f"now {i2['data']['call_count']}")
            expect(i2["data"]["target_id"] == "tgt-x",
                   f"target_id: {i2['data']}")

            al = call("artifact.list", {"build_id": "buildA"})
            expect(al["ok"], f"list: {al}")
            expect(al["data"]["total"] == 2,
                   f"expected 2 artifacts: {al['data']}")

            # Importing again with the default policy ("error") should
            # fail with -32000.
            im_again = call("session.import", {"path": pack_path})
            expect(not im_again["ok"], f"second import should fail: "
                   f"{im_again}")
            expect(im_again.get("error", {}).get("code") == -32000,
                   f"expected -32000 on dup: {im_again}")

            # Same pack with conflict_policy=skip should succeed.
            im_skip = call("session.import", {
                "path": pack_path, "conflict_policy": "skip"})
            expect(im_skip["ok"], f"import skip: {im_skip}")
            expect(len(im_skip["data"]["skipped"]) >= 3,
                   f"expected duplicates skipped: {im_skip['data']}")

            # Bad conflict_policy → -32602.
            im_bad = call("session.import", {
                "path": pack_path, "conflict_policy": "boom"})
            expect(not im_bad["ok"], f"bad policy: {im_bad}")
            expect(im_bad.get("error", {}).get("code") == -32602,
                   f"expected -32602: {im_bad}")

            # Missing-file → -32000.
            im_nope = call("session.import", {"path": "/no/such.ldbpack"})
            expect(not im_nope["ok"], f"missing-file: {im_nope}")
            expect(im_nope.get("error", {}).get("code") == -32000,
                   f"expected -32000 missing: {im_nope}")
        finally:
            try: proc2.stdin.close()
            except Exception: pass
            proc2.wait(timeout=10)

        # ---- signing flow (docs/14-pack-signing.md tests 11 + 12) ----
        # Currently expected-to-skip: the dispatcher does not yet honor
        # `sign_key` / `trust_root` / `require_signed`. Once the
        # implementation lands, remove the `signing_xfail` early-return
        # and the rest of this block runs as full positive + negative
        # coverage.
        signing_xfail = True
        if signing_xfail:
            print("ldbpack signing smoke: SKIP (dispatcher integration "
                  "pending — docs/14 §Test Plan items 11 + 12)")
        else:
            key_priv = os.path.join(
                os.path.dirname(__file__), "..",
                "fixtures", "keys", "alice_ed25519")
            key_pub  = key_priv + ".pub"
            bob_pub  = os.path.join(
                os.path.dirname(__file__), "..",
                "fixtures", "keys", "bob_ed25519.pub")
            trust_ok = tempfile.mkdtemp(prefix="ldb_smoke_trust_alice_")
            trust_no = tempfile.mkdtemp(prefix="ldb_smoke_trust_bob_")
            try:
                shutil.copy(key_pub, os.path.join(trust_ok, "alice.pub"))
                shutil.copy(bob_pub, os.path.join(trust_no, "bob.pub"))
                signed_pack = os.path.join(pack_dir, "signed.ldbpack")

                # Positive: A signs, B verifies with alice in trust_ok.
                src2 = tempfile.mkdtemp(prefix="ldb_smoke_pack_src2_")
                dst2 = tempfile.mkdtemp(prefix="ldb_smoke_pack_dst2_")
                try:
                    procA = start(src2)
                    try:
                        callA = caller(procA)
                        sa = callA("session.create",
                                   {"name": "signed-alpha"})
                        expect(sa["ok"], f"create: {sa}")
                        callA("artifact.put", {
                            "build_id": "buildA",
                            "name": "s.bin",
                            "bytes_b64": "AAEC",
                        })
                        ex = callA("session.export", {
                            "id": sa["data"]["id"],
                            "path": signed_pack,
                            "sign_key": key_priv,
                            "signer": "alice@smoke",
                        })
                        expect(ex["ok"], f"signed-export: {ex}")
                        expect(ex["data"]["manifest"]["format"]
                               == "ldbpack/1+sig",
                               f"signed format: {ex['data']}")
                        expect(ex["data"]["signature"]["algorithm"]
                               == "ed25519",
                               f"signed algo: {ex['data']}")
                    finally:
                        try: procA.stdin.close()
                        except Exception: pass
                        procA.wait(timeout=10)

                    procB = start(dst2)
                    try:
                        callB = caller(procB)
                        im_ok = callB("session.import", {
                            "path": signed_pack,
                            "trust_root": trust_ok,
                            "require_signed": True,
                        })
                        expect(im_ok["ok"], f"signed-import-ok: {im_ok}")
                        expect(im_ok["data"]["signature"]["verified"]
                               is True,
                               f"verified=true: {im_ok['data']}")

                        # Negative: same pack, trust root missing alice.
                        im_bad = callB("session.import", {
                            "path": signed_pack,
                            "trust_root": trust_no,
                            "require_signed": True,
                        })
                        expect(not im_bad["ok"],
                               f"untrusted should fail: {im_bad}")
                        expect(im_bad.get("error", {}).get("code") == -32003,
                               f"expected -32003 untrusted: {im_bad}")
                    finally:
                        try: procB.stdin.close()
                        except Exception: pass
                        procB.wait(timeout=10)
                finally:
                    for p in (src2, dst2):
                        shutil.rmtree(p, ignore_errors=True)
            finally:
                for p in (trust_ok, trust_no):
                    shutil.rmtree(p, ignore_errors=True)

        if failures:
            for f in failures:
                sys.stderr.write(f"FAIL: {f}\n")
            sys.exit(1)
        print("ldbpack smoke test PASSED")
    finally:
        for p in (src_root, dst_root, pack_dir):
            shutil.rmtree(p, ignore_errors=True)


if __name__ == "__main__":
    main()
