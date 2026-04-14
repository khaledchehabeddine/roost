---
name: rust-code-review
description: Run the Rust code reviewer on all changed code
---

## Steps

### 1. Gather context

Run `git branch --show-current` and `git diff --name-only main -- '*.rs' | sort`.

### 2. Review

Invoke the `rust-code-reviewer` agent on the changed files listed above.

### 3. Report

Present the agent's **Summary** to the user.
