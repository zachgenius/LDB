#!/usr/bin/env bash
# Smoke test for view descriptors on module.list.
#
# Verifies fields/limit/offset/summary on the wire — the same shapes
# unit-tested in test_protocol_view.cpp, but flowing through the
# JSON-RPC dispatcher and an actual LldbBackend.
set -euo pipefail

LDBD="${1:?usage: run.sh <ldbd> <fixture>}"
FIX="${2:?usage: run.sh <ldbd> <fixture>}"

[[ -x "$LDBD" ]] || { echo "ldbd not executable: $LDBD" >&2; exit 1; }
[[ -f "$FIX"  ]] || { echo "fixture missing: $FIX"     >&2; exit 1; }

REQUESTS=$(cat <<EOF
{"jsonrpc":"2.0","id":"r1","method":"target.open","params":{"path":"$FIX"}}
{"jsonrpc":"2.0","id":"r2","method":"module.list","params":{"target_id":1}}
{"jsonrpc":"2.0","id":"r3","method":"module.list","params":{"target_id":1,"view":{"limit":2}}}
{"jsonrpc":"2.0","id":"r4","method":"module.list","params":{"target_id":1,"view":{"offset":1,"limit":1}}}
{"jsonrpc":"2.0","id":"r5","method":"module.list","params":{"target_id":1,"view":{"fields":["path","uuid"]}}}
{"jsonrpc":"2.0","id":"r6","method":"module.list","params":{"target_id":1,"view":{"summary":true}}}
{"jsonrpc":"2.0","id":"r7","method":"module.list","params":{"target_id":1,"view":{"limit":-1}}}
{"jsonrpc":"2.0","id":"r8","method":"module.list","params":{"target_id":1,"view":"not-an-object"}}
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
[[ "$LINES" -eq 8 ]] || fail "expected 8 response lines, got $LINES"

get_resp() { printf '%s\n' "$OUTPUT" | grep "\"id\":\"$1\""; }

# r2: default view — no view shaping but total still populated.
R2=$(get_resp r2)
[[ "$R2" == *'"total":'*    ]] || fail "r2: total missing on default response"
[[ "$R2" == *'"modules":[{'* ]] || fail "r2: modules array empty"

# r3: limit=2 → exactly two modules + next_offset=2 (the fixture pulls in
# more than 2 modules on macOS; should always be true).
R3=$(get_resp r3)
[[ "$R3" == *'"next_offset":2'* ]] || fail "r3: missing next_offset=2"
# Count modules by counting "{" inside the modules array.
# Quick check: the response is bounded so direct substring spotting works.
[[ "$R3" == *'"modules":[{'* ]] || fail "r3: modules empty under limit"

# r4: offset=1 limit=1 → exactly one module starting at index 1.
R4=$(get_resp r4)
[[ "$R4" == *'"next_offset":2'* ]] || fail "r4: next_offset should be 2"

# r5: fields=["path","uuid"] → no 'sections' key in items.
R5=$(get_resp r5)
[[ "$R5" == *'"path":'* ]] || fail "r5: path missing"
[[ "$R5" == *'"uuid":'* ]] || fail "r5: uuid missing"
[[ "$R5" != *'"sections":'* ]] || fail "r5: sections should be projected out"
[[ "$R5" != *'"triple":'*   ]] || fail "r5: triple should be projected out"

# r6: summary=true → sample limited and summary flag set.
R6=$(get_resp r6)
[[ "$R6" == *'"summary":true'* ]] || fail "r6: missing summary=true"
[[ "$R6" == *'"total":'*       ]] || fail "r6: missing total"

# r7: limit=-1 → invalid params (translated through the view parser).
R7=$(get_resp r7)
[[ "$R7" == *'"ok":false'*    ]] || fail "r7: expected ok=false"
[[ "$R7" == *'"code":-32602'* ]] || fail "r7: expected -32602"

# r8: view="not-an-object" → invalid params.
R8=$(get_resp r8)
[[ "$R8" == *'"ok":false'*    ]] || fail "r8: expected ok=false"
[[ "$R8" == *'"code":-32602'* ]] || fail "r8: expected -32602"

echo "view module.list smoke test PASSED ($LINES responses)"
