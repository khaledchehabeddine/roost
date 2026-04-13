---
name: security-audit
description: Run the security auditor on all changed code
disable-model-invocation: true
allowed-tools: Bash(git *)
---

## Context

- Current branch: !`git branch --show-current`
- Changed files: !`git diff --name-only main...HEAD`

## Task

- Invoke `security-auditor` agent on all changed files
- Present the agent's **Security Summary** rating to the user
