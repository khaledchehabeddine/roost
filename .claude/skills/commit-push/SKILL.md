---
name: commit-push
description: Use only when the user explicitly asks to stage, commit, push, or create or update a draft pull request. Not for review-only requests, merge, force-push, rebase, or cherry-pick workflows.
disable-model-invocation: true
allowed-tools: Agent Bash(gh pr create*) Bash(gh pr edit*) Bash(gh pr list*) Bash(gh pr view*) Bash(git add*) Bash(git branch*) Bash(git commit*) Bash(git diff*) Bash(git log*) Bash(git ls-files*) Bash(git rev-parse*) Bash(git status*) Bash(git switch*) Bash(scripts/check.sh *) Bash(scripts/push-reviewed-branch.sh) Read
---

Read [SKILL.md](../../../.agents/instructions/skills/commit-push/SKILL.md).
