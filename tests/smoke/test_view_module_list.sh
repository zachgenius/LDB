#!/usr/bin/env bash
# Smoke test for view descriptors on module.list.
#
# Verifies fields/limit/offset/summary on the wire — the same shapes
# unit-tested in test_protocol_view.cpp, but flowing through the
# JSON-RPC dispatcher and an actual LldbBackend.
#
# Cross-platform note: a freshly-opened ELF target has only the
# executable in its module list (Linux loads ld-linux + libs only on
# process launch), while Mach-O target.open already pulls in dyld and
# system libs. To get a deterministic >=2-module state on both
# platforms we launch the inferior with stop_at_entry, run the view
# tests, then kill. We use the sleeper fixture so the inferior won't
# exit out from under us on a slow CI box.
set -euo pipefail

LDBD="${1:?usage: run.sh <ldbd> <fixture>}"
FIX="${2:?usage: run.sh <ldbd> <fixture>}"

[[ -x "$LDBD" ]] || { echo "ldbd not executable: $LDBD" >&2; exit 1; }
[[ -f "$FIX"  ]] || { echo "fixture missing: $FIX"     >&2; exit 1; }

REQUESTS=$(cat <<EOF
{"jsonrpc":"2.0","id":"r1","method":"target.open","params":{"path":"$FIX"}}
{"jsonrpc":"2.0","id":"r2","method":"process.launch","params":{"target_id":1,"stop_at_entry":true}}
{"jsonrpc":"2.0","id":"r3","method":"module.list","params":{"target_id":1}}
{"jsonrpc":"2.0","id":"r4","method":"module.list","params":{"target_id":1,"view":{"limit":1}}}
{"jsonrpc":"2.0","id":"r5","method":"module.list","params":{"target_id":1,"view":{"fields":["path","uuid"]}}}
{"jsonrpc":"2.0","id":"r6","method":"module.list","params":{"target_id":1,"view":{"summary":true}}}
{"jsonrpc":"2.0","id":"r7","method":"module.list","params":{"target_id":1,"view":{"limit":-1}}}
{"jsonrpc":"2.0","id":"r8","method":"module.list","params":{"target_id":1,"view":"not-an-object"}}
{"jsonrpc":"2.0","id":"r9","method":"process.kill","params":{"target_id":1}}
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
[[ "$LINES" -eq 9 ]] || fail "expected 9 response lines, got $LINES"

get_resp() { printf '%s\n' "$OUTPUT" | grep "\"id\":\"$1\""; }

# r2: process.launch must succeed; subsequent module.list relies on the
# inferior being live so the dynamic loader and its modules are present.
R2=$(get_resp r2)
[[ "$R2" == *'"ok":true'*  ]] || fail "r2: process.launch failed (no live process → no multi-module state)"
[[ "$R2" == *'"state":"stopped"'* ]] || fail "r2: expected stopped state at entry"

# r3: default view — modules array non-empty, total populated.
R3=$(get_resp r3)
[[ "$R3" == *'"total":'*    ]] || fail "r3: total missing on default response"
[[ "$R3" == *'"modules":[{'* ]] || fail "r3: modules array empty"

# r4: limit=1 → exactly one module + (since total>=2 on both platforms after
# launch) next_offset=1 indicating more pages exist.
R4=$(get_resp r4)
[[ "$R4" == *'"next_offset":1'* ]] || fail "r4: missing next_offset=1 (need total>=2 modules; check that process.launch loaded the dynamic loader)"
[[ "$R4" == *'"modules":[{'* ]] || fail "r4: modules empty under limit=1"

# r5: fields=["path","uuid"] → no 'sections' / 'triple' keys in items.
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

# r9: process.kill — clean up; sleeper would otherwise hang around.
R9=$(get_resp r9)
[[ "$R9" == *'"ok":true'*     ]] || fail "r9: process.kill failed"

echo "view module.list smoke test PASSED ($LINES responses)"
