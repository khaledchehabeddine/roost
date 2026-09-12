---
description: Create a GitHub issue and link it to the project board
argument-hint: [title]
disable-model-invocation: true
allowed-tools: Bash(gh *) Bash(python3 *) Read Write
---

Use `$ARGUMENTS` as the proposed title when supplied.

When creating a GitHub issue:

1. Read [the shared tracker guide](../../../docs/agents/issue-tracker.md) before any tracker operation. It owns repository verification, issue types, templates, labels, milestones, project membership and safe payload handling.
2. Build the issue from the request and the appropriate scaffold. Reuse supplied answers and ask only for missing fields or choices required by the guide.
3. Inspect the complete payload for sensitive content, then create the authorized issue and add it to the project using the guide's operations. Report its URL and any incomplete project step separately.
