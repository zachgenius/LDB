#!/usr/bin/env bash
# Smoke test for the process.* JSON-RPC endpoints.
#
# Lifecycle: open → state(none) → launch(stop_at_entry) → state(stopped)
#         → continue → state(exited) → state on second target_id (none).
set -euo pipefail

LDBD="${1:?usage: run.sh <ldbd> <fixture>}"
FIX="${2:?usage: run.sh <ldbd> <fixture>}"

[[ -x "$LDBD" ]] || { echo "ldbd not executable: $LDBD" >&2; exit 1; }
[[ -f "$FIX"  ]] || { echo "fixture missing: $FIX"     >&2; exit 1; }

REQUESTS=$(cat <<EOF
{"jsonrpc":"2.0","id":"r1","method":"target.open","params":{"path":"$FIX"}}
{"jsonrpc":"2.0","id":"r2","method":"process.state","params":{"target_id":1}}
{"jsonrpc":"2.0","id":"r3","method":"process.launch","params":{"target_id":1,"stop_at_entry":true}}
{"jsonrpc":"2.0","id":"r4","method":"process.state","params":{"target_id":1}}
{"jsonrpc":"2.0","id":"r5","method":"process.continue","params":{"target_id":1}}
{"jsonrpc":"2.0","id":"r6","method":"process.state","params":{"target_id":1}}
{"jsonrpc":"2.0","id":"r7","method":"process.continue","params":{"target_id":1}}
{"jsonrpc":"2.0","id":"r8","method":"process.kill","params":{"target_id":1}}
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

# r2: state before launch is "none".
R2=$(get_resp r2)
[[ "$R2" == *'"state":"none"'* ]] || fail "r2: expected state=none"

# r3: launch with stop_at_entry → state=stopped, pid present.
R3=$(get_resp r3)
[[ "$R3" == *'"state":"stopped"'* ]] || fail "r3: expected state=stopped"
[[ "$R3" == *'"pid":'*            ]] || fail "r3: missing pid"

# r4: subsequent state agrees.
R4=$(get_resp r4)
[[ "$R4" == *'"state":"stopped"'* ]] || fail "r4: expected state=stopped"

# r5: continue → state=exited (structs returns immediately).
R5=$(get_resp r5)
[[ "$R5" == *'"state":"exited"'* ]] || fail "r5: expected state=exited after continue"
[[ "$R5" == *'"exit_code":'*    ]] || fail "r5: missing exit_code"

# r6: state remains exited.
R6=$(get_resp r6)
[[ "$R6" == *'"state":"exited"'* ]] || fail "r6: expected state=exited"

# r7: continue on exited process → backend error (-32000).
R7=$(get_resp r7)
[[ "$R7" == *'"ok":false'*    ]] || fail "r7: expected ok=false on continue-after-exit"
[[ "$R7" == *'"code":-32000'* ]] || fail "r7: expected backend error code -32000"

# r8: kill on exited → idempotent (no error). State still exited or none.
R8=$(get_resp r8)
[[ "$R8" == *'"ok":true'* ]] || fail "r8: kill should be idempotent on exited process"

echo "process smoke test PASSED ($LINES responses)"
