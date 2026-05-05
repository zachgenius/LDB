#!/usr/bin/env bash
# Smoke test for the string.list JSON-RPC endpoint.
set -euo pipefail

LDBD="${1:?usage: run.sh <ldbd> <fixture>}"
FIX="${2:?usage: run.sh <ldbd> <fixture>}"

[[ -x "$LDBD" ]] || { echo "ldbd not executable: $LDBD" >&2; exit 1; }
[[ -f "$FIX"  ]] || { echo "fixture missing: $FIX"     >&2; exit 1; }

REQUESTS=$(cat <<EOF
{"jsonrpc":"2.0","id":"r1","method":"target.open","params":{"path":"$FIX"}}
{"jsonrpc":"2.0","id":"r2","method":"string.list","params":{"target_id":1}}
{"jsonrpc":"2.0","id":"r3","method":"string.list","params":{"target_id":1,"min_len":10}}
{"jsonrpc":"2.0","id":"r4","method":"string.list","params":{"target_id":1,"min_len":100}}
{"jsonrpc":"2.0","id":"r5","method":"string.list","params":{"target_id":1,"section":"__NOPE__"}}
{"jsonrpc":"2.0","id":"r6","method":"string.list","params":{"target_id":1,"min_len":-5}}
EOF
)

OUTPUT=$(printf '%s\n' "$REQUESTS" | "$LDBD" --stdio --log-level error 2>/dev/null)

fail() {
  echo "FAIL: $1" >&2
  printf '%s\n' "$OUTPUT" | head -c 4096 >&2
  echo >&2
  exit 1
}

LINES=0
while IFS= read -r _; do LINES=$((LINES + 1)); done <<< "$OUTPUT"
[[ "$LINES" -eq 6 ]] || fail "expected 6 response lines, got $LINES"

get_resp() { printf '%s\n' "$OUTPUT" | grep "\"id\":\"$1\""; }

# r2: default scan finds both fixture strings.
R2=$(get_resp r2)
[[ "$R2" == *'"text":"btp_schema.xml"'* ]] || fail "r2: missing btp_schema.xml"
[[ "$R2" == *'"text":"DXP/1.0"'*        ]] || fail "r2: missing DXP/1.0"

# r3: min_len=10 excludes "DXP/1.0" (7) but keeps "btp_schema.xml" (14).
R3=$(get_resp r3)
[[ "$R3" == *'"text":"btp_schema.xml"'* ]] || fail "r3: missing btp_schema.xml"
[[ "$R3" != *'"text":"DXP/1.0"'*        ]] || fail "r3: DXP/1.0 should have been filtered out"

# r4: min_len=100 excludes everything from the fixture.
R4=$(get_resp r4)
[[ "$R4" != *'"text":"btp_schema.xml"'* ]] || fail "r4: btp_schema.xml should have been filtered out"
[[ "$R4" != *'"text":"DXP/1.0"'*        ]] || fail "r4: DXP/1.0 should have been filtered out"

# r5: nonexistent section → empty.
R5=$(get_resp r5)
[[ "$R5" == *'"strings":[]'* ]] || fail "r5: expected empty strings[]"

# r6: negative min_len → invalid params.
R6=$(get_resp r6)
[[ "$R6" == *'"ok":false'*    ]] || fail "r6: expected ok=false for negative min_len"
[[ "$R6" == *'"code":-32602'* ]] || fail "r6: expected -32602"

echo "string.list smoke test PASSED ($LINES responses)"
