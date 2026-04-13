---
name: security-audit
description: Run the security auditor on all source files
---

## Steps

### 1. Gather context

Run `git branch --show-current` and `find crates -name '*.rs' | sort`.

### 2. Audit

Invoke the `security-auditor` agent on all source files listed above.

### 3. Report

Present the agent's **Security Summary** rating to the user.
