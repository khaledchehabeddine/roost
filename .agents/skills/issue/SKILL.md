---
name: issue
description: Create a GitHub issue from the request and link it to the project board. Not for editing, closing, or triaging existing issues.
---

# Create issue

## Workflow

1. Read [the shared tracker guide](../../../docs/agents/issue-tracker.md) before any tracker operation. It owns repository verification, issue types, templates, labels, milestones, project membership and safe payload handling.
2. Build the issue from the request and the appropriate scaffold. Reuse supplied answers and ask only for missing fields or choices required by the guide.
3. Inspect the complete payload for sensitive content, then create the authorized issue and add it to the project using the guide's operations. Report its URL and any incomplete project step separately.
