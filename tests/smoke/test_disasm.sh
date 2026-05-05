#!/usr/bin/env bash
# Smoke test for disasm.range and disasm.function.
set -euo pipefail

LDBD="${1:?usage: run.sh <ldbd> <fixture>}"
FIX="${2:?usage: run.sh <ldbd> <fixture>}"

[[ -x "$LDBD" ]] || { echo "ldbd not executable: $LDBD" >&2; exit 1; }
[[ -f "$FIX"  ]] || { echo "fixture missing: $FIX"     >&2; exit 1; }

REQUESTS=$(cat <<EOF
{"jsonrpc":"2.0","id":"r1","method":"target.open","params":{"path":"$FIX"}}
{"jsonrpc":"2.0","id":"r2","method":"disasm.function","params":{"target_id":1,"name":"point2_distance_sq"}}
{"jsonrpc":"2.0","id":"r3","method":"disasm.function","params":{"target_id":1,"name":"definitely_not_a_function"}}
{"jsonrpc":"2.0","id":"r4","method":"disasm.range","params":{"target_id":1,"start_addr":0,"end_addr":0}}
{"jsonrpc":"2.0","id":"r5","method":"disasm.range","params":{"target_id":1,"end_addr":100}}
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

# r2: disasm.function found the symbol and returned instructions.
R2=$(get_resp r2)
[[ "$R2" == *'"found":true'*           ]] || fail "r2: expected found=true"
[[ "$R2" == *'"instructions":[{'*      ]] || fail "r2: missing instructions array"
[[ "$R2" == *'"mnemonic":'*            ]] || fail "r2: missing mnemonic field"
[[ "$R2" == *'"bytes":'*               ]] || fail "r2: missing bytes field"
[[ "$R2" == *'"address":'*             ]] || fail "r2: missing address field"

# r3: disasm.function on an unknown name → found=false, no instructions.
R3=$(get_resp r3)
[[ "$R3" == *'"found":false'*  ]] || fail "r3: expected found=false"
[[ "$R3" != *'"instructions"'* ]] || fail "r3: instructions should be absent on miss"

# r4: empty range → empty instructions array.
R4=$(get_resp r4)
[[ "$R4" == *'"instructions":[]'* ]] || fail "r4: expected empty instructions"

# r5: missing start_addr → invalid params.
R5=$(get_resp r5)
[[ "$R5" == *'"ok":false'*    ]] || fail "r5: expected ok=false"
[[ "$R5" == *'"code":-32602'* ]] || fail "r5: expected -32602"

echo "disasm smoke test PASSED ($LINES responses)"
