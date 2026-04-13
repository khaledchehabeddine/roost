---
name: security-audit
description: Run the security auditor on all changed code
---

## Steps

### 1. Gather context

Run `git branch --show-current` and `git diff --name-only main...HEAD`.

### 2. Audit

Invoke the `security-auditor` agent on all changed files.

### 3. Report

Present the agent's **Security Summary** rating to the user.
