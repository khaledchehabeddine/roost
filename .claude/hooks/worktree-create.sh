#!/usr/bin/env bash
set -euo pipefail

worktree_path=$(jq -r .worktree_path)
git worktree add --detach "$worktree_path" origin/HEAD >&2

if [[ -f .worktreeinclude ]]; then
  while IFS= read -r pattern; do
    [[ -z "$pattern" || "$pattern" =~ ^[[:space:]]*# ]] && continue
    [[ -e "$pattern" ]] || continue
    dst="$worktree_path/$pattern"
    mkdir -p "$(dirname "$dst")"
    cp -R "$pattern" "$dst"
  done < .worktreeinclude
fi

echo "$worktree_path"
