#!/bin/bash
# Nudge to capture learnings when fixes or discoveries are detected.
# Non-blocking — approves the stop with an optional system message.

CONTEXT=$(cat)

# Skip if this is already a stop hook re-entry
if echo "$CONTEXT" | grep -q '"stop_hook_active":true'; then
  echo '{"decision":"approve"}'
  exit 0
fi

DISCOVERY_PATTERNS="fixed|workaround|gotcha|that's wrong|check again|we already|should have|discovered|realized|turns out|actually uses|not .* but"

if echo "$CONTEXT" | grep -qiE "$DISCOVERY_PATTERNS"; then
  cat << 'EOF'
{
  "decision": "approve",
  "systemMessage": "This session involved fixes or discoveries. Consider creating a decision record (/create-decision-record) or updating CLAUDE.md if anything non-obvious was learned."
}
EOF
else
  echo '{"decision":"approve"}'
fi
