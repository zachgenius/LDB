#!/usr/bin/env bash
# Smoke test: target.open returns a summary by default; full section
# tables are gated behind view.include_sections=true.
#
# Motivation: on a 503 MB iOS Mach-O with 587 top-level sections, the
# pre-fix target.open response was 2.2 MB of inline section data per
# call. We want the default response cheap (path/uuid/triple/section_count
# only) and let the caller opt back in to full sections when they need
# them.
set -euo pipefail

LDBD="${1:?usage: run.sh <ldbd> <fixture>}"
FIX="${2:?usage: run.sh <ldbd> <fixture>}"

[[ -x "$LDBD" ]] || { echo "ldbd not executable: $LDBD" >&2; exit 1; }
[[ -f "$FIX"  ]] || { echo "fixture missing: $FIX"     >&2; exit 1; }

REQUESTS=$(cat <<EOF
{"jsonrpc":"2.0","id":"r1","method":"target.open","params":{"path":"$FIX"}}
{"jsonrpc":"2.0","id":"r2","method":"target.open","params":{"path":"$FIX","view":{"include_sections":true}}}
{"jsonrpc":"2.0","id":"r3","method":"target.open","params":{"path":"$FIX","view":{"include_sections":false}}}
EOF
)

OUTPUT=$(printf '%s\n' "$REQUESTS" | "$LDBD" --stdio --log-level error 2>/dev/null)

fail() {
  echo "FAIL: $1" >&2
  printf '%s\n' "$OUTPUT" | head -c 4096 >&2
  echo >&2
  exit 1
}

get_resp() { printf '%s\n' "$OUTPUT" | grep "\"id\":\"$1\""; }

# r1: default view — no inline sections, but section_count is set.
R1=$(get_resp r1)
[[ "$R1" == *'"ok":true'*       ]] || fail "r1: default target.open failed"
[[ "$R1" == *'"section_count":'* ]] || fail "r1: default response missing section_count"
[[ "$R1" != *'"sections":['*    ]] || fail "r1: default response should NOT inline sections array"

# r2: view.include_sections=true — sections array present.
R2=$(get_resp r2)
[[ "$R2" == *'"ok":true'*       ]] || fail "r2: target.open with include_sections=true failed"
[[ "$R2" == *'"sections":[{'*   ]] || fail "r2: explicit include_sections=true must return non-empty sections array"
[[ "$R2" == *'"section_count":'* ]] || fail "r2: section_count must also be present when sections are included"

# r3: view.include_sections=false — same shape as default.
R3=$(get_resp r3)
[[ "$R3" == *'"ok":true'*       ]] || fail "r3: target.open with include_sections=false failed"
[[ "$R3" == *'"section_count":'* ]] || fail "r3: section_count missing"
[[ "$R3" != *'"sections":['*    ]] || fail "r3: explicit include_sections=false must not inline sections"

echo "target.open view smoke test PASSED"
