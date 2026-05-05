#!/usr/bin/env bash
# M0 smoke test: spawn ldbd, send a few requests, check responses.
#
# Note: avoid `printf "$BIG" | grep -q` patterns — pipefail + early grep exit
# triggers SIGPIPE on the upstream printf and the pipeline fails. We use bash
# string matching on the captured output instead.
set -euo pipefail

LDBD="${1:?usage: run.sh <path-to-ldbd>}"

if [[ ! -x "$LDBD" ]]; then
  echo "ldbd binary not found or not executable: $LDBD" >&2
  exit 1
fi

TARGET_BIN="${LDB_TEST_TARGET:-/bin/ls}"
if [[ ! -f "$TARGET_BIN" ]]; then
  echo "test target not found: $TARGET_BIN" >&2
  exit 1
fi

REQUESTS=$(cat <<EOF
{"jsonrpc":"2.0","id":"r1","method":"hello"}
{"jsonrpc":"2.0","id":"r2","method":"describe.endpoints"}
{"jsonrpc":"2.0","id":"r3","method":"target.open","params":{"path":"$TARGET_BIN"}}
{"jsonrpc":"2.0","id":"r4","method":"module.list","params":{"target_id":1}}
{"jsonrpc":"2.0","id":"r5","method":"target.close","params":{"target_id":1}}
EOF
)

OUTPUT=$(printf '%s\n' "$REQUESTS" | "$LDBD" --stdio --log-level error 2>/dev/null)

fail() {
  echo "FAIL: $1" >&2
  echo "--- daemon output ---" >&2
  printf '%s\n' "$OUTPUT" | head -c 8192 >&2
  echo >&2
  exit 1
}

# Each response is one JSON object on its own line. Five requests, five lines.
LINES=0
while IFS= read -r _; do LINES=$((LINES + 1)); done <<< "$OUTPUT"
[[ "$LINES" -eq 5 ]] || fail "expected 5 response lines, got $LINES"

# All responses ok:true.
[[ "$OUTPUT" != *'"ok":false'* ]] || fail 'one or more responses reported ok:false'

# r1: hello response identifies daemon.
[[ "$OUTPUT" == *'"name":"ldbd"'*       ]] || fail 'hello missing name=ldbd'
[[ "$OUTPUT" == *'"version":"'*         ]] || fail 'hello missing version'
[[ "$OUTPUT" == *'"protocol":{"major"'* ]] || fail 'hello missing protocol version'

# r2: endpoint catalog non-empty.
[[ "$OUTPUT" == *'"method":"target.open"'* ]] || fail 'describe.endpoints missing target.open'

# r3: target.open returned a target_id and at least one module.
[[ "$OUTPUT" == *'"target_id":1'* ]] || fail 'target.open did not return target_id=1'
[[ "$OUTPUT" == *'"modules":[{'*  ]] || fail 'target.open modules array empty'

# r4: module.list returned modules.
# (Same shape; both responses contain "modules":[{... }])

# r5: clean close.
[[ "$OUTPUT" == *'"closed":true'* ]] || fail 'target.close did not return closed=true'

echo "smoke test PASSED ($LINES responses)"
