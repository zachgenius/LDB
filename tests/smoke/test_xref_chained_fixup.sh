#!/usr/bin/env bash
# Smoke test for docs/35-field-report-followups.md §3 phase 2 — the
# xref pipeline must follow chained-fixup slot indirection on Apple
# silicon arm64 binaries built with -Wl,-fixup_chains.
#
# The fixture ldb_fix_chain_slot has:
#   - a string literal "ldb_chain_test_marker_string" in __TEXT/__cstring
#   - a pointer slot g_slot in __DATA/__data, encoded as a chained-fixup
#     rebase that resolves (at dyld-time) to that string
#   - reference_string() which loads through the slot via ADRP+LDR.
#
# Without the phase-2 wire-up, xref.addr against the string's file
# address returns empty. With phase 2, the LDR inside reference_string
# is surfaced as an xref attributed to that function.
set -euo pipefail

LDBD="${1:?usage: test_xref_chained_fixup.sh <ldbd> <fixture>}"
FIX="${2:?usage: test_xref_chained_fixup.sh <ldbd> <fixture>}"

[[ -x "$LDBD" ]] || { echo "ldbd not executable: $LDBD" >&2; exit 1; }
[[ -f "$FIX"  ]] || { echo "fixture missing: $FIX"     >&2; exit 1; }

# Step 1: open the fixture, find the string's file address.
SETUP=$(cat <<EOF
{"jsonrpc":"2.0","id":"r1","method":"target.open","params":{"path":"$FIX"}}
{"jsonrpc":"2.0","id":"r2","method":"string.list","params":{"target_id":1,"min_len":20}}
EOF
)

SETUP_OUT=$(printf '%s\n' "$SETUP" | "$LDBD" --stdio --log-level error 2>/dev/null)

ADDR=$(printf '%s\n' "$SETUP_OUT" \
  | grep '"id":"r2"' \
  | python3 -c '
import sys, json
resp = json.loads(sys.stdin.read())
for s in resp["data"]["strings"]:
    if s["text"] == "ldb_chain_test_marker_string":
        print(s["addr"])
        break
')

if [[ -z "$ADDR" ]]; then
  echo "FAIL: could not locate ldb_chain_test_marker_string in string.list" >&2
  echo "$SETUP_OUT" >&2
  exit 1
fi

# Step 2: actual xref tests.
REQUESTS=$(cat <<EOF
{"jsonrpc":"2.0","id":"r1","method":"target.open","params":{"path":"$FIX"}}
{"jsonrpc":"2.0","id":"r2","method":"xref.addr","params":{"target_id":1,"addr":$ADDR}}
{"jsonrpc":"2.0","id":"r3","method":"string.xref","params":{"target_id":1,"text":"ldb_chain_test_marker_string"}}
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
[[ "$LINES" -eq 3 ]] || fail "expected 3 response lines, got $LINES"

get_resp() { printf '%s\n' "$OUTPUT" | grep "\"id\":\"$1\""; }

# r2: xref.addr against the string addr must include at least one match
# attributed to reference_string, with an LDR mnemonic (the slot load).
R2=$(get_resp r2)
[[ "$R2" == *'"matches":[{'*                 ]] || fail "r2: matches array empty — chained-fixup wire-up missing?"
[[ "$R2" == *'"function":"reference_string"'* ]] || fail "r2: no match attributed to reference_string"

# r3: string.xref delegates to xref_address; same expectation.
R3=$(get_resp r3)
[[ "$R3" == *'"text":"ldb_chain_test_marker_string"'* ]] || fail "r3: missing string round-trip"
[[ "$R3" == *'"function":"reference_string"'*         ]] || fail "r3: no xref attributed to reference_string"

echo "xref chained-fixup smoke test PASSED ($LINES responses; target=$ADDR)"
