#!/usr/bin/env bash
# Smoke test for the type.layout JSON-RPC endpoint.
#
# Opens the structs fixture and verifies the wire JSON shape for the
# four known struct layouts. Mirrors the C++ unit tests but on the
# wire surface.
set -euo pipefail

LDBD="${1:?usage: run.sh <ldbd> <fixture>}"
FIX="${2:?usage: run.sh <ldbd> <fixture>}"

[[ -x "$LDBD" ]] || { echo "ldbd not executable: $LDBD" >&2; exit 1; }
[[ -f "$FIX"  ]] || { echo "fixture missing: $FIX" >&2; exit 1; }

REQUESTS=$(cat <<EOF
{"jsonrpc":"2.0","id":"r1","method":"target.open","params":{"path":"$FIX"}}
{"jsonrpc":"2.0","id":"r2","method":"type.layout","params":{"target_id":1,"name":"point2"}}
{"jsonrpc":"2.0","id":"r3","method":"type.layout","params":{"target_id":1,"name":"stride_pad"}}
{"jsonrpc":"2.0","id":"r4","method":"type.layout","params":{"target_id":1,"name":"dxp_login_frame"}}
{"jsonrpc":"2.0","id":"r5","method":"type.layout","params":{"target_id":1,"name":"nope_does_not_exist"}}
{"jsonrpc":"2.0","id":"r6","method":"type.layout","params":{"target_id":1}}
EOF
)

OUTPUT=$(printf '%s\n' "$REQUESTS" | "$LDBD" --stdio --log-level error 2>/dev/null)

fail() {
  echo "FAIL: $1" >&2
  echo "--- daemon output ---" >&2
  printf '%s\n' "$OUTPUT" | head -c 8192 >&2
  echo >&2
  exit 1
}

# We expect 6 responses (one per request).
LINES=0
while IFS= read -r _; do LINES=$((LINES + 1)); done <<< "$OUTPUT"
[[ "$LINES" -eq 6 ]] || fail "expected 6 response lines, got $LINES"

# r1 ok, r2/r3/r4 ok with layout, r5 ok with empty/nullopt, r6 invalid params.

# r1: target.open succeeded.
[[ "$OUTPUT" == *'"target_id":1'* ]] || fail "r1: target.open didn't return target_id=1"

# r2: point2 — 8 bytes, no holes.
[[ "$OUTPUT" == *'"name":"point2"'*    ]] || fail "r2: missing name=point2"
[[ "$OUTPUT" == *'"byte_size":8'*      ]] || fail "r2: missing byte_size=8"
[[ "$OUTPUT" == *'"holes_total":0'*    ]] || fail "r2: missing holes_total=0"
[[ "$OUTPUT" == *'"name":"x"'*         ]] || fail "r2: missing field x"
[[ "$OUTPUT" == *'"name":"y"'*         ]] || fail "r2: missing field y"

# r3: stride_pad — 3-byte hole.
[[ "$OUTPUT" == *'"name":"stride_pad"'* ]] || fail "r3: missing name=stride_pad"
[[ "$OUTPUT" == *'"holes_total":3'*     ]] || fail "r3: missing holes_total=3"
[[ "$OUTPUT" == *'"holes_after":3'*     ]] || fail "r3: missing field-level holes_after=3"

# r4: dxp_login_frame — 4-byte hole, 16 bytes total, alignment 8.
[[ "$OUTPUT" == *'"name":"dxp_login_frame"'* ]] || fail "r4: missing name=dxp_login_frame"
[[ "$OUTPUT" == *'"byte_size":16'*           ]] || fail "r4: missing byte_size=16"
[[ "$OUTPUT" == *'"alignment":8'*            ]] || fail "r4: missing alignment=8"
[[ "$OUTPUT" == *'"holes_total":4'*          ]] || fail "r4: missing holes_total=4"
[[ "$OUTPUT" == *'"holes_after":4'*          ]] || fail "r4: missing field-level holes_after=4"
[[ "$OUTPUT" == *'"name":"sid"'*             ]] || fail "r4: missing field sid"

# r5: unknown type — ok response, found=false.
[[ "$OUTPUT" == *'"r5"'* ]] || fail "r5: response not present"
# We require an explicit found=false signal to disambiguate from an empty layout.
[[ "$OUTPUT" == *'"r5","jsonrpc":"2.0","ok":true'* ]] || fail "r5: expected ok=true with found=false"
[[ "$OUTPUT" == *'"found":false'* ]] || fail "r5: expected found=false for unknown type"

# r6: missing 'name' param — error response.
[[ "$OUTPUT" == *'"r6"'* ]] || fail "r6: response not present"
[[ "$OUTPUT" == *'"id":"r6"'*       ]] || fail "r6: id mismatch"
[[ "$OUTPUT" == *'"ok":false'*      ]] || fail "r6: expected ok=false"
[[ "$OUTPUT" == *'"code":-32602'*   ]] || fail "r6: expected kInvalidParams (-32602)"

echo "type.layout smoke test PASSED ($LINES responses)"
