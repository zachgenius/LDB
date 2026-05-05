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

# Extract one response line by id so each match is scoped to a single
# request — avoids cross-line false positives that the previous
# substring-of-everything approach was susceptible to.
get_resp() { printf '%s\n' "$OUTPUT" | grep "\"id\":\"$1\""; }

R1=$(get_resp r1)
[[ "$R1" == *'"target_id":1'* ]] || fail "r1: target.open didn't return target_id=1"

# r2: point2 — 8 bytes, no holes.
R2=$(get_resp r2)
[[ "$R2" == *'"name":"point2"'*    ]] || fail "r2: missing name=point2"
[[ "$R2" == *'"byte_size":8'*      ]] || fail "r2: missing byte_size=8"
[[ "$R2" == *'"holes_total":0'*    ]] || fail "r2: missing holes_total=0"
[[ "$R2" == *'"name":"x"'*         ]] || fail "r2: missing field x"
[[ "$R2" == *'"name":"y"'*         ]] || fail "r2: missing field y"

# r3: stride_pad — 3-byte hole.
R3=$(get_resp r3)
[[ "$R3" == *'"name":"stride_pad"'* ]] || fail "r3: missing name=stride_pad"
[[ "$R3" == *'"holes_total":3'*     ]] || fail "r3: missing holes_total=3"
[[ "$R3" == *'"holes_after":3'*     ]] || fail "r3: missing field-level holes_after=3"

# r4: dxp_login_frame — 4-byte hole, 16 bytes total, alignment 8.
R4=$(get_resp r4)
[[ "$R4" == *'"name":"dxp_login_frame"'* ]] || fail "r4: missing name=dxp_login_frame"
[[ "$R4" == *'"byte_size":16'*           ]] || fail "r4: missing byte_size=16"
[[ "$R4" == *'"alignment":8'*            ]] || fail "r4: missing alignment=8"
[[ "$R4" == *'"holes_total":4'*          ]] || fail "r4: missing holes_total=4"
[[ "$R4" == *'"holes_after":4'*          ]] || fail "r4: missing field-level holes_after=4"
[[ "$R4" == *'"name":"sid"'*             ]] || fail "r4: missing field sid"

# r5: unknown type — ok response, found=false.
R5=$(get_resp r5)
[[ -n "$R5"                ]] || fail "r5: response not present"
[[ "$R5" == *'"ok":true'*  ]] || fail "r5: expected ok=true with found=false"
[[ "$R5" == *'"found":false'* ]] || fail "r5: expected found=false for unknown type"

# r6: missing 'name' param — error response.
R6=$(get_resp r6)
[[ -n "$R6"                ]] || fail "r6: response not present"
[[ "$R6" == *'"ok":false'* ]] || fail "r6: expected ok=false"
[[ "$R6" == *'"code":-32602'* ]] || fail "r6: expected kInvalidParams (-32602)"

echo "type.layout smoke test PASSED ($LINES responses)"
