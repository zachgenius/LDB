#!/usr/bin/env python3
"""Smoke-check the daemon-level hello capability block."""
import json
import os
import subprocess
import sys


def usage():
    sys.stderr.write(
        "usage: test_hello_capabilities.py <ldbd> <expected-disasm-backend>\n"
    )
    sys.exit(2)


def main():
    if len(sys.argv) != 3:
        usage()
    ldbd = sys.argv[1]
    expected = sys.argv[2]
    if expected not in ("lldb", "capstone"):
        usage()
    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n")
        sys.exit(1)

    req = {"jsonrpc": "2.0", "id": "h-cap", "method": "hello"}
    proc = subprocess.Popen(
        [ldbd, "--stdio", "--log-level", "error"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    proc.stdin.write(json.dumps(req) + "\n")
    proc.stdin.close()
    line = proc.stdout.readline()
    proc.wait(timeout=5)
    if not line:
        stderr = proc.stderr.read()
        sys.stderr.write(f"daemon closed stdout (stderr was: {stderr})\n")
        sys.exit(1)

    resp = json.loads(line)
    if resp.get("ok") is not True:
        sys.stderr.write(f"hello failed: {resp}\n")
        sys.exit(1)

    caps = resp.get("data", {}).get("capabilities", {})
    actual = caps.get("disasm_backend")
    if actual != expected:
        sys.stderr.write(
            f"expected disasm_backend={expected!r}, got {actual!r}: {caps}\n"
        )
        sys.exit(1)
    if expected == "capstone" and caps.get("disasm_fallback") is not True:
        sys.stderr.write(f"capstone hello missing disasm_fallback=true: {caps}\n")
        sys.exit(1)
    if expected == "lldb" and "disasm_fallback" in caps:
        sys.stderr.write(f"lldb hello should not report disasm_fallback: {caps}\n")
        sys.exit(1)

    print(f"OK: hello capabilities disasm_backend={actual}")


if __name__ == "__main__":
    main()
