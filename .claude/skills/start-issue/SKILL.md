---
name: start-issue
description: Fetch a GitHub issue, create a branch, and begin implementation
argument-hint: <issue-id>
disable-model-invocation: true
allowed-tools: Bash(gh *), Bash(git *)
---

## Context

- Current branch: !`git branch --show-current`
- Issue: !`gh issue view $ARGUMENTS --json number,title,body,labels`

## Task

1. Parse the issue's single label and title from the context above
2. Derive the branch name as `<label>/<issue-title-kebab-case>`
3. Confirm the branch name with the user
4. Run `git checkout -b <branch-name>`
5. Run `gh issue develop $ARGUMENTS --name <branch-name>` to link the branch to the issue
6. Present the issue title, description, and acceptance criteria to the user and begin implementation
