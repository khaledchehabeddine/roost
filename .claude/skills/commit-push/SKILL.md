---
description: Stage, commit, push, and create or update a pull request following CONTRIBUTING.md conventions
argument-hint: [issue-id]
disable-model-invocation: true
allowed-tools: Bash(gh *), Bash(git *)
---

## Context

- Current branch: !`git branch --show-current`
- Current status: !`git status`
- Staged diff: !`git diff --staged`
- Current diff against main: !`git diff main...HEAD`

## Task

### 1. Branch check

If the current branch is `main`:

If `$ARGUMENTS` is provided:
- Fetch the issue: `gh issue view $ARGUMENTS --json number,title,labels`
- Use the issue's single label directly as the branch type
- Create branch as `<label>/<issue-title-kebab-case>` and confirm with the user
- Run `git checkout -b <branch-name>`
- Run `gh issue develop $ARGUMENTS --checkout` to link the branch to the issue

If `$ARGUMENTS` is not provided:
- Fetch available repo labels: `gh label list --json name`
- Ask the user to select a label from the fetched list and provide a short description
- Create branch as `<selected-label>/<short-description>` and confirm with the user
- Run `git checkout -b <branch-name>`

### 2. Commit

- Infer the commit message from the staged diff following the format in `CONTRIBUTING.md`
- Confirm the commit message with the user
- Run `git add -A && git commit -m "<message>"`

### 3. Push

- Run `git push -u origin HEAD`

### 4. Pull request

PR title: derive from branch name as `<Type>: <Short Description>`, capitalize keywords.
PR body: derive from `git diff main...HEAD` — reflects current state only, not commit history. Use the template in `PULL_REQUEST_TEMPLATE.md` for the body structure.

If no open PR exists:
- Run `gh pr create --title "<title>" --body "<body>" --draft --assignee "@me" --label "<branch-type>"`

If a PR already exists:
- Run `gh pr edit --body "<body>"`

## Additional Resources

- For commit message format, see [CONTRIBUTING.md](../../../CONTRIBUTING.md)
- For PR body structure, see [PULL_REQUEST_TEMPLATE.md](../../../.github/PULL_REQUEST_TEMPLATE.md)
