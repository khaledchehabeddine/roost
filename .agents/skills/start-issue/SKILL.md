---
name: start-issue
description: Trigger when the user wants to begin working on a GitHub issue by creating a branch and linking it. Not for issues already in progress or general branching without an issue.
---

## Steps

1. Run `gh issue view <id> --json number,title,body,labels` to fetch the issue
2. Run `git branch --show-current` to check the current branch
3. Parse the issue's label and title
4. Derive branch name as `<label>/<issue-title-kebab-case>`, confirm with user
5. Run `git checkout -b <branch-name>`
6. Run `gh issue develop <id> --name <branch-name>`
7. Present the issue title, description, and acceptance criteria, then begin implementation
