#!/usr/bin/env bash
# Smoke test for the symbol.find JSON-RPC endpoint.
set -euo pipefail

LDBD="${1:?usage: run.sh <ldbd> <fixture>}"
FIX="${2:?usage: run.sh <ldbd> <fixture>}"

[[ -x "$LDBD" ]] || { echo "ldbd not executable: $LDBD" >&2; exit 1; }
[[ -f "$FIX"  ]] || { echo "fixture missing: $FIX"     >&2; exit 1; }

REQUESTS=$(cat <<EOF
{"jsonrpc":"2.0","id":"r1","method":"target.open","params":{"path":"$FIX"}}
{"jsonrpc":"2.0","id":"r2","method":"symbol.find","params":{"target_id":1,"name":"point2_distance_sq"}}
{"jsonrpc":"2.0","id":"r3","method":"symbol.find","params":{"target_id":1,"name":"g_origin"}}
{"jsonrpc":"2.0","id":"r4","method":"symbol.find","params":{"target_id":1,"name":"g_origin","kind":"function"}}
{"jsonrpc":"2.0","id":"r5","method":"symbol.find","params":{"target_id":1,"name":"point2_distance_sq","kind":"variable"}}
{"jsonrpc":"2.0","id":"r6","method":"symbol.find","params":{"target_id":1,"name":"definitely_not_a_thing"}}
{"jsonrpc":"2.0","id":"r7","method":"symbol.find","params":{"target_id":1,"name":"main","kind":"banana"}}
{"jsonrpc":"2.0","id":"r8","method":"symbol.find","params":{"target_id":1,"name":"point2_distance_sq","view":{"fields":["name","kind"]}}}
EOF
)

OUTPUT=$(printf '%s\n' "$REQUESTS" | "$LDBD" --stdio --log-level error 2>/dev/null)

fail() {
  echo "FAIL: $1" >&2
  printf '%s\n' "$OUTPUT" | head -c 8192 >&2
  echo >&2
  exit 1
}

LINES=0
while IFS= read -r _; do LINES=$((LINES + 1)); done <<< "$OUTPUT"
[[ "$LINES" -eq 8 ]] || fail "expected 8 response lines, got $LINES"

# Extract one response line by id. nlohmann::json serializes with keys
# in alphabetical order, so per-id lines have a stable shape.
get_resp() { printf '%s\n' "$OUTPUT" | grep "\"id\":\"$1\""; }

R2=$(get_resp r2)
[[ "$R2" == *'"name":"point2_distance_sq"'* ]] || fail "r2: missing function name"
[[ "$R2" == *'"kind":"function"'*           ]] || fail "r2: kind not function"

R3=$(get_resp r3)
[[ "$R3" == *'"name":"g_origin"'* ]] || fail "r3: missing g_origin"
[[ "$R3" == *'"kind":"variable"'* ]] || fail "r3: kind not variable"
[[ "$R3" == *'"sz":8'*            ]] || fail "r3: missing sz=8"

R4=$(get_resp r4)
[[ "$R4" == *'"matches":[]'*  ]] || fail "r4: expected empty matches (kind=function vs variable)"
[[ "$R4" == *'"ok":true'*     ]] || fail "r4: expected ok=true"

R5=$(get_resp r5)
[[ "$R5" == *'"matches":[]'* ]] || fail "r5: expected empty matches (kind=variable vs function)"

R6=$(get_resp r6)
[[ "$R6" == *'"matches":[]'* ]] || fail "r6: expected empty matches for unknown name"

R7=$(get_resp r7)
[[ "$R7" == *'"ok":false'*    ]] || fail "r7: expected ok=false"
[[ "$R7" == *'"code":-32602'* ]] || fail "r7: expected kInvalidParams (-32602)"

# r8: view.fields=["name","kind"] should drop addr / sz / module from
# each match (proves view projection ran on this previously-bare
# endpoint), and "total" should appear at the response level.
R8=$(get_resp r8)
[[ "$R8" == *'"ok":true'*                   ]] || fail "r8: expected ok=true"
[[ "$R8" == *'"name":"point2_distance_sq"'* ]] || fail "r8: missing name in projected match"
[[ "$R8" == *'"kind":"function"'*           ]] || fail "r8: missing kind in projected match"
[[ "$R8" == *'"addr":'*                     ]] && fail "r8: 'addr' should be projected out"
[[ "$R8" == *'"sz":'*                       ]] && fail "r8: 'sz' should be projected out"
[[ "$R8" == *'"module":'*                   ]] && fail "r8: 'module' should be projected out"
[[ "$R8" == *'"total":'*                    ]] || fail "r8: missing 'total' from view envelope"

echo "symbol.find smoke test PASSED ($LINES responses)"
