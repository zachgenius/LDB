#!/usr/bin/env python3
"""Smoke test for the CBOR wire transport (M5 part 3).

Spawns ldbd with `--format=cbor` and exercises the stdio loop with
length-prefixed CBOR frames:

  • single `hello` request → ok response with `version` field;
  • multi-request session: hello + describe.endpoints + target.close,
    each round-tripped over the binary wire.

Frame layout: 4-byte big-endian uint32 length, then N bytes of CBOR.
We hand-roll encode/decode using the `cbor2` package only if available;
otherwise fall back to a tiny ad-hoc encoder/decoder for the small subset
of CBOR shapes ldbd actually emits (maps, strings, ints, bools, null,
arrays). The stdlib has no CBOR support.
"""
import os
import struct
import subprocess
import sys

# --- Tiny CBOR encoder/decoder (RFC 8949 subset) -------------------------
#
# Just enough for the request shapes we send (small maps of strings to
# strings/ints/objects) and the response shapes ldbd returns (maps with
# string keys, arrays, ints, strings, bools, null). No tags, no big
# integers, no half-floats. Matches what nlohmann::json::to_cbor produces
# for our payloads.

def _enc_uint(major, n, out):
    if n < 24:
        out.append((major << 5) | n)
    elif n < 1 << 8:
        out.append((major << 5) | 24); out.append(n)
    elif n < 1 << 16:
        out.append((major << 5) | 25); out += struct.pack(">H", n)
    elif n < 1 << 32:
        out.append((major << 5) | 26); out += struct.pack(">I", n)
    else:
        out.append((major << 5) | 27); out += struct.pack(">Q", n)


def cbor_encode(v):
    out = bytearray()
    _enc(v, out)
    return bytes(out)


def _enc(v, out):
    if v is None:
        out.append(0xf6)
    elif v is True:
        out.append(0xf5)
    elif v is False:
        out.append(0xf4)
    elif isinstance(v, bool):
        out.append(0xf5 if v else 0xf4)
    elif isinstance(v, int):
        if v >= 0:
            _enc_uint(0, v, out)
        else:
            _enc_uint(1, -1 - v, out)
    elif isinstance(v, str):
        b = v.encode("utf-8")
        _enc_uint(3, len(b), out)
        out += b
    elif isinstance(v, (bytes, bytearray)):
        _enc_uint(2, len(v), out)
        out += v
    elif isinstance(v, list):
        _enc_uint(4, len(v), out)
        for x in v:
            _enc(x, out)
    elif isinstance(v, dict):
        _enc_uint(5, len(v), out)
        for k, x in v.items():
            _enc(k, out)
            _enc(x, out)
    else:
        raise TypeError(f"unsupported type for cbor encode: {type(v)}")


def _read_uint(buf, i, info):
    if info < 24:
        return info, i
    if info == 24:
        return buf[i], i + 1
    if info == 25:
        return struct.unpack_from(">H", buf, i)[0], i + 2
    if info == 26:
        return struct.unpack_from(">I", buf, i)[0], i + 4
    if info == 27:
        return struct.unpack_from(">Q", buf, i)[0], i + 8
    raise ValueError(f"unsupported additional info {info}")


def _dec(buf, i):
    b = buf[i]; i += 1
    major = b >> 5
    info = b & 0x1f
    if major == 0:
        n, i = _read_uint(buf, i, info)
        return n, i
    if major == 1:
        n, i = _read_uint(buf, i, info)
        return -1 - n, i
    if major == 2:
        n, i = _read_uint(buf, i, info)
        return bytes(buf[i:i + n]), i + n
    if major == 3:
        n, i = _read_uint(buf, i, info)
        return buf[i:i + n].decode("utf-8"), i + n
    if major == 4:
        n, i = _read_uint(buf, i, info)
        out = []
        for _ in range(n):
            v, i = _dec(buf, i)
            out.append(v)
        return out, i
    if major == 5:
        n, i = _read_uint(buf, i, info)
        out = {}
        for _ in range(n):
            k, i = _dec(buf, i)
            v, i = _dec(buf, i)
            out[k] = v
        return out, i
    if major == 7:
        if info == 20: return False, i
        if info == 21: return True, i
        if info == 22: return None, i
        if info == 23: return None, i  # undefined → None for our purposes
        if info == 26:
            v, = struct.unpack_from(">f", buf, i); return v, i + 4
        if info == 27:
            v, = struct.unpack_from(">d", buf, i); return v, i + 8
        raise ValueError(f"unsupported simple/float info {info}")
    raise ValueError(f"unsupported major type {major}")


def cbor_decode(buf):
    v, i = _dec(buf, 0)
    if i != len(buf):
        raise ValueError(f"trailing bytes: consumed {i} of {len(buf)}")
    return v


# --- Wire framing --------------------------------------------------------

def write_frame(stream, payload):
    body = cbor_encode(payload)
    stream.write(struct.pack(">I", len(body)))
    stream.write(body)
    stream.flush()


def read_frame(stream):
    prefix = stream.read(4)
    if len(prefix) == 0:
        return None
    if len(prefix) != 4:
        raise IOError(f"short prefix read: got {len(prefix)} bytes")
    n, = struct.unpack(">I", prefix)
    body = stream.read(n)
    if len(body) != n:
        raise IOError(f"short body read: wanted {n}, got {len(body)}")
    return cbor_decode(body)


# --- Test harness --------------------------------------------------------

def usage():
    sys.stderr.write("usage: test_cbor.py <ldbd>\n")
    sys.exit(2)


def main():
    if len(sys.argv) != 2:
        usage()
    ldbd = sys.argv[1]
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n"); sys.exit(1)

    env = dict(os.environ)
    env.setdefault("LLDB_LOG_LEVEL", "error")
    proc = subprocess.Popen(
        [ldbd, "--stdio", "--format", "cbor", "--log-level", "error"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )

    next_id = [0]
    def call(method, params=None):
        next_id[0] += 1
        rid = f"r{next_id[0]}"
        req = {"jsonrpc": "2.0", "id": rid, "method": method,
               "params": params or {}}
        write_frame(proc.stdin, req)
        resp = read_frame(proc.stdout)
        if resp is None:
            stderr = proc.stderr.read().decode("utf-8", errors="replace")
            sys.stderr.write(f"daemon closed stdout (stderr was: {stderr})\n")
            sys.exit(1)
        return resp

    failures = []
    def expect(cond, msg):
        if not cond: failures.append(msg)

    try:
        # --- single hello ----------------------------------------------
        r1 = call("hello")
        expect(r1.get("ok") is True, f"hello: {r1}")
        expect(r1.get("id") == "r1", f"hello id mismatch: {r1!r}")
        data = r1.get("data") or {}
        expect("version" in data, f"hello.data.version missing: {data!r}")

        # --- multi-request session -------------------------------------
        r2 = call("describe.endpoints")
        expect(r2.get("ok") is True, f"describe.endpoints: {r2}")
        endpoints = (r2.get("data") or {}).get("endpoints") or []
        methods = {e.get("method") for e in endpoints}
        expect("hello" in methods,
               f"hello not in describe.endpoints over CBOR")
        expect(len(methods) > 10,
               f"endpoints count too low ({len(methods)}); CBOR encode/decode "
               f"likely truncated")

        r3 = call("target.close")
        # target.close with no open target may succeed (no-op) or return
        # a typed error — we just verify we got a well-formed response.
        expect("ok" in r3, f"target.close malformed: {r3}")
        expect(r3.get("id") == "r3", f"target.close id mismatch: {r3!r}")

        # --- bad request: garbage CBOR triggers a typed error ----------
        # Send an unknown method; we should get ok:false back over CBOR.
        r4 = call("no.such.method")
        expect(r4.get("ok") is False,
               f"unknown-method should return ok:false: {r4}")
        err = r4.get("error") or {}
        expect(err.get("code") == -32601,
               f"unknown-method code: {err}")

    finally:
        proc.stdin.close()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    if failures:
        sys.stderr.write("FAILURES:\n")
        for f in failures:
            sys.stderr.write(f"  - {f}\n")
        sys.exit(1)
    print("OK")


if __name__ == "__main__":
    main()
