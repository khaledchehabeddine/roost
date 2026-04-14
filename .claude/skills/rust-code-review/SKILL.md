---
name: rust-code-review
description: Run the Rust code reviewer on all changed code
disable-model-invocation: true
allowed-tools: Bash(git *)
---

## Context

- Current branch: !`git branch --show-current`
- Changed Rust files: !`git diff --name-only main -- '*.rs' | sort`

## Task

- Invoke `rust-code-reviewer` agent on the changed files listed above
- Present the agent's **Summary** to the user
