#!/usr/bin/env bash
set -euo pipefail

COMMAND=$(jq -r '.tool_input.command // ""' 2>/dev/null) || COMMAND=""
if [[ "$COMMAND" == git\ commit* ]]; then
  exec bash "$(dirname "$0")/audit.sh"
fi
