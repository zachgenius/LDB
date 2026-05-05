#!/usr/bin/env bash
# Smoke test for xref.addr.
#
# Plan:
#   1. open the fixture
#   2. find point2_distance_sq → addr
#   3. xref.addr against that addr → expect ≥1 match attributed to main
#   4. xref.addr against a clearly-bogus addr → expect empty
#   5. missing addr param → -32602
set -euo pipefail

LDBD="${1:?usage: run.sh <ldbd> <fixture>}"
FIX="${2:?usage: run.sh <ldbd> <fixture>}"

[[ -x "$LDBD" ]] || { echo "ldbd not executable: $LDBD" >&2; exit 1; }
[[ -f "$FIX"  ]] || { echo "fixture missing: $FIX"     >&2; exit 1; }

# Step 1+2: open and resolve the function address.
SETUP=$(cat <<EOF
{"jsonrpc":"2.0","id":"r1","method":"target.open","params":{"path":"$FIX"}}
{"jsonrpc":"2.0","id":"r2","method":"symbol.find","params":{"target_id":1,"name":"point2_distance_sq"}}
EOF
)

SETUP_OUT=$(printf '%s\n' "$SETUP" | "$LDBD" --stdio --log-level error 2>/dev/null)

ADDR=$(printf '%s\n' "$SETUP_OUT" \
  | grep '"id":"r2"' \
  | python3 -c 'import sys,json; print(json.loads(sys.stdin.read())["data"]["matches"][0]["addr"])')

if [[ -z "$ADDR" || "$ADDR" == "0" ]]; then
  echo "FAIL: could not resolve point2_distance_sq from setup output" >&2
  echo "$SETUP_OUT" >&2
  exit 1
fi

# Step 3-5: actual xref tests.
REQUESTS=$(cat <<EOF
{"jsonrpc":"2.0","id":"r1","method":"target.open","params":{"path":"$FIX"}}
{"jsonrpc":"2.0","id":"r2","method":"xref.addr","params":{"target_id":1,"addr":$ADDR}}
{"jsonrpc":"2.0","id":"r3","method":"xref.addr","params":{"target_id":1,"addr":3735879680}}
{"jsonrpc":"2.0","id":"r4","method":"xref.addr","params":{"target_id":1}}
EOF
)
# 3735879680 = 0xDEAD0000

OUTPUT=$(printf '%s\n' "$REQUESTS" | "$LDBD" --stdio --log-level error 2>/dev/null)

fail() {
  echo "FAIL: $1" >&2
  printf '%s\n' "$OUTPUT" | head -c 4096 >&2
  echo >&2
  exit 1
}

LINES=0
while IFS= read -r _; do LINES=$((LINES + 1)); done <<< "$OUTPUT"
[[ "$LINES" -eq 4 ]] || fail "expected 4 response lines, got $LINES"

get_resp() { printf '%s\n' "$OUTPUT" | grep "\"id\":\"$1\""; }

# r2: at least one match attributed to main, in the bl/call family.
R2=$(get_resp r2)
[[ "$R2" == *'"matches":[{'*  ]] || fail "r2: matches array empty"
[[ "$R2" == *'"function":"main"'* ]] || fail "r2: expected at least one match in main"
[[ "$R2" == *'"mnemonic":"bl"'* || \
   "$R2" == *'"mnemonic":"b"'*  || \
   "$R2" == *'"mnemonic":"call"'* || \
   "$R2" == *'"mnemonic":"callq"'* ]] || fail "r2: missing branch/call mnemonic"

# r3: bogus addr → empty matches.
R3=$(get_resp r3)
[[ "$R3" == *'"matches":[]'* ]] || fail "r3: expected empty matches for bogus address"

# r4: missing addr param → -32602.
R4=$(get_resp r4)
[[ "$R4" == *'"ok":false'*    ]] || fail "r4: expected ok=false"
[[ "$R4" == *'"code":-32602'* ]] || fail "r4: expected -32602"

echo "xref.addr smoke test PASSED ($LINES responses; target=$ADDR)"
