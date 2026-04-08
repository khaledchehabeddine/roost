---
name: start-issue
description: Start work on a GitHub issue
argument-hint: <issue-id>
disable-model-invocation: true
allowed-tools: Bash(gh *) Bash(git *)
---

## Context

- Current branch: !`git branch --show-current`
- Issue: !`gh issue view $ARGUMENTS --json number,title,body,labels`

## Task

1. Parse the issue's single label and title from the context above
2. Derive the branch name as `<label>/<issue-title-kebab-case>`, confirm with user
3. `git checkout -b <branch-name>`
4. `gh issue develop $ARGUMENTS --name <branch-name>`
5. Present the issue title, description, and acceptance criteria to the user and begin implementation
