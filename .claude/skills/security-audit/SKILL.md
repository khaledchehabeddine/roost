---
name: security-audit
description: Run the security auditor on changed crypto and core code
disable-model-invocation: true
allowed-tools: Bash(git *)
---

## Context

- Current branch: !`git branch --show-current`
- Changed files: !`git diff --name-only main...HEAD`

## Task

- Invoke `security-auditor` agent on all changed files under `crates/hermes-crypto/` and `crates/hermes-core/`
- If no crypto or core files changed, run the agent on the full diff — general checks (input validation, dependency hygiene, DoS, logging) still apply
- Present the agent's **Security Summary** rating to the user
