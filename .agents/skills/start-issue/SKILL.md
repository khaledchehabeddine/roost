---
name: start-issue
description: Start work on a GitHub issue. Accepts an issue ID as input.
---

## Steps

1. Run `gh issue view <id> --json number,title,body,labels` to fetch the issue
2. Run `git branch --show-current` to check the current branch
3. Parse the issue's label and title
4. Derive branch name as `<label>/<issue-title-kebab-case>`, confirm with user
5. Run `git checkout -b <branch-name>`
6. Run `gh issue develop <id> --name <branch-name>`
7. Present the issue title, description, and acceptance criteria, then begin implementation
