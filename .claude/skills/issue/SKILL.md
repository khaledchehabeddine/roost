---
name: issue
description: Use only when the user explicitly asks to create a new GitHub issue and add it to the project. Not for editing, closing, or triaging existing issues.
argument-hint: [title]
disable-model-invocation: true
allowed-tools: Bash(gh api --method GET*) Bash(gh issue create*) Bash(gh label list*) Read
---

Read [SKILL.md](../../../.agents/instructions/skills/issue/SKILL.md).
