#!/usr/bin/env python3
"""End-to-end smoke for the `hello` protocol-version handshake (Tier 1
§3a, see docs/05-protocol-versioning.md).

Cases:
  * No params → response carries protocol{version,major,minor,min_supported}.
  * `protocol_min` equal to current → ok.
  * `protocol_min` lower than current → ok (daemon satisfies floor).
  * `protocol_min` higher than current minor → -32011.
  * `protocol_min` higher major → -32011.
  * Malformed `protocol_min` (string) → -32602.
  * Numeric `protocol_min` → -32602.
  * Empty-string `protocol_min` → -32602.

The daemon's current version + min_supported are read from its own
`hello` response so this test stays correct as those constants move.
"""
import json
import os
import subprocess
import sys


def usage():
    sys.stderr.write("usage: test_hello_handshake.py <ldbd>\n")
    sys.exit(2)


def main():
    if len(sys.argv) != 2:
        usage()
    ldbd = sys.argv[1]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n")
        sys.exit(1)

    failures = []

    def expect(cond, msg):
        if not cond:
            failures.append(msg)

    def call(req):
        proc = subprocess.Popen(
            [ldbd, "--stdio", "--log-level", "error"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True, bufsize=1,
        )
        proc.stdin.write(json.dumps(req) + "\n")
        proc.stdin.close()
        line = proc.stdout.readline()
        proc.wait(timeout=5)
        if not line:
            stderr = proc.stderr.read()
            raise RuntimeError(f"daemon closed stdout (stderr was: {stderr})")
        return json.loads(line)

    # --- baseline: no params -----------------------------------------
    r = call({"jsonrpc": "2.0", "id": "h1", "method": "hello"})
    expect(r.get("ok") is True, f"no-params hello not ok: {r}")
    data = r.get("data", {})
    proto = data.get("protocol", {})
    for k in ("version", "major", "minor", "min_supported"):
        expect(k in proto, f"protocol.{k} missing: {proto}")
    expect(isinstance(proto.get("major"), int),
           f"protocol.major not int: {proto.get('major')!r}")
    expect(isinstance(proto.get("minor"), int),
           f"protocol.minor not int: {proto.get('minor')!r}")
    expect(isinstance(proto.get("version"), str),
           f"protocol.version not string: {proto.get('version')!r}")
    expect(isinstance(proto.get("min_supported"), str),
           f"protocol.min_supported not string: {proto.get('min_supported')!r}")
    expect(proto.get("version") == f"{proto.get('major')}.{proto.get('minor')}",
           f"protocol.version mismatch with major.minor: {proto}")

    cur_major = proto["major"]
    cur_minor = proto["minor"]
    cur_str   = proto["version"]
    min_str   = proto["min_supported"]

    # --- equal floor: ok ---------------------------------------------
    r = call({"jsonrpc": "2.0", "id": "h2", "method": "hello",
              "params": {"protocol_min": cur_str}})
    expect(r.get("ok") is True, f"protocol_min={cur_str!r} not ok: {r}")

    # --- min_supported floor: ok (daemon at >= min_supported) -------
    r = call({"jsonrpc": "2.0", "id": "h3", "method": "hello",
              "params": {"protocol_min": min_str}})
    expect(r.get("ok") is True, f"protocol_min={min_str!r} not ok: {r}")

    # --- below current minor: ok -------------------------------------
    if cur_minor > 0:
        below = f"{cur_major}.{cur_minor - 1}"
        r = call({"jsonrpc": "2.0", "id": "h4", "method": "hello",
                  "params": {"protocol_min": below}})
        expect(r.get("ok") is True, f"protocol_min={below!r} not ok: {r}")
    # also "0.0" (always servable as floor by 0.x daemon)
    if cur_major == 0:
        r = call({"jsonrpc": "2.0", "id": "h4b", "method": "hello",
                  "params": {"protocol_min": "0.0"}})
        expect(r.get("ok") is True, f"protocol_min=\"0.0\" not ok: {r}")

    # --- above current minor: -32011 ---------------------------------
    above = f"{cur_major}.{cur_minor + 1}"
    r = call({"jsonrpc": "2.0", "id": "h5", "method": "hello",
              "params": {"protocol_min": above}})
    expect(r.get("ok") is False,
           f"protocol_min={above!r} unexpectedly ok: {r}")
    if r.get("ok") is False:
        err = r.get("error", {})
        expect(err.get("code") == -32011,
               f"protocol_min={above!r} wrong code: {err}")
        expect(above in err.get("message", ""),
               f"error message missing requested version: {err}")
        expect(cur_str in err.get("message", ""),
               f"error message missing daemon version: {err}")

    # --- above current major: -32011 ---------------------------------
    higher_major = f"{cur_major + 1}.0"
    r = call({"jsonrpc": "2.0", "id": "h6", "method": "hello",
              "params": {"protocol_min": higher_major}})
    expect(r.get("ok") is False,
           f"protocol_min={higher_major!r} unexpectedly ok: {r}")
    if r.get("ok") is False:
        expect(r.get("error", {}).get("code") == -32011,
               f"protocol_min={higher_major!r} wrong code: {r.get('error')}")

    # --- malformed string: -32602 ------------------------------------
    for bad in ["abc", "", "1", "1.", ".1", "1.1.1", " 1.0", "1.0a"]:
        r = call({"jsonrpc": "2.0", "id": "h7", "method": "hello",
                  "params": {"protocol_min": bad}})
        expect(r.get("ok") is False,
               f"malformed protocol_min={bad!r} unexpectedly ok: {r}")
        if r.get("ok") is False:
            expect(r.get("error", {}).get("code") == -32602,
                   f"malformed protocol_min={bad!r} wrong code: {r.get('error')}")

    # --- numeric protocol_min: -32602 --------------------------------
    r = call({"jsonrpc": "2.0", "id": "h8", "method": "hello",
              "params": {"protocol_min": 0.1}})
    expect(r.get("ok") is False, f"numeric protocol_min unexpectedly ok: {r}")
    if r.get("ok") is False:
        expect(r.get("error", {}).get("code") == -32602,
               f"numeric protocol_min wrong code: {r.get('error')}")

    if failures:
        for f in failures:
            sys.stderr.write(f"FAIL: {f}\n")
        sys.exit(1)
    print(f"OK: hello handshake (daemon protocol={cur_str}, "
          f"min_supported={min_str})")


if __name__ == "__main__":
    main()
