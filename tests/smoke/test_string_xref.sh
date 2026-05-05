#!/usr/bin/env bash
# Smoke test for string.xref — the user's RE workflow primitive.
#
# Asserts that querying for "btp_schema.xml" produces at least one
# xref attributed to main. This is the workflow described in
# docs/02-ldb-mvp-plan.md §5.
set -euo pipefail

LDBD="${1:?usage: run.sh <ldbd> <fixture>}"
FIX="${2:?usage: run.sh <ldbd> <fixture>}"

[[ -x "$LDBD" ]] || { echo "ldbd not executable: $LDBD" >&2; exit 1; }
[[ -f "$FIX"  ]] || { echo "fixture missing: $FIX"     >&2; exit 1; }

REQUESTS=$(cat <<EOF
{"jsonrpc":"2.0","id":"r1","method":"target.open","params":{"path":"$FIX"}}
{"jsonrpc":"2.0","id":"r2","method":"string.xref","params":{"target_id":1,"text":"btp_schema.xml"}}
{"jsonrpc":"2.0","id":"r3","method":"string.xref","params":{"target_id":1,"text":"DXP/1.0"}}
{"jsonrpc":"2.0","id":"r4","method":"string.xref","params":{"target_id":1,"text":"definitely_not_in_fixture_42"}}
{"jsonrpc":"2.0","id":"r5","method":"string.xref","params":{"target_id":1}}
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
[[ "$LINES" -eq 5 ]] || fail "expected 5 response lines, got $LINES"

get_resp() { printf '%s\n' "$OUTPUT" | grep "\"id\":\"$1\""; }

# r2: btp_schema.xml has at least one xref attributed to main.
R2=$(get_resp r2)
[[ "$R2" == *'"text":"btp_schema.xml"'* ]] || fail "r2: missing string round-trip"
[[ "$R2" == *'"function":"main"'*       ]] || fail "r2: no xref attributed to main"
[[ "$R2" == *'"xrefs":[{'*              ]] || fail "r2: xrefs array empty"

# r3: same for DXP/1.0.
R3=$(get_resp r3)
[[ "$R3" == *'"text":"DXP/1.0"'*  ]] || fail "r3: missing string round-trip"
[[ "$R3" == *'"function":"main"'* ]] || fail "r3: no xref attributed to main"

# r4: unknown text → empty results.
R4=$(get_resp r4)
[[ "$R4" == *'"results":[]'* ]] || fail "r4: expected empty results"

# r5: missing text param → -32602.
R5=$(get_resp r5)
[[ "$R5" == *'"ok":false'*    ]] || fail "r5: expected ok=false"
[[ "$R5" == *'"code":-32602'* ]] || fail "r5: expected -32602"

echo "string.xref smoke test PASSED ($LINES responses)"
