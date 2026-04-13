---
name: security-audit
description: Run the security auditor on all changed code
disable-model-invocation: true
allowed-tools: Bash(git *)
---

## Context

- Current branch: !`git branch --show-current`
- Source files: !`find crates -name '*.rs' | sort`

## Task

- Invoke `security-auditor` agent on all source files listed above
- Present the agent's **Security Summary** rating to the user
