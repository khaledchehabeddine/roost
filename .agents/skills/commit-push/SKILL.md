---
name: commit-push
description: Stage, commit, push, and create or update a pull request. Optionally accepts an issue ID to link the branch.
---

## Steps

### 1. Branch check

Run `git branch --show-current` and `git status`.

If on `main` with an issue ID provided:
- Run `gh issue view <id> --json number,title,labels`
- Derive branch as `<label>/<issue-title-kebab-case>`, confirm with user
- Run `git checkout -b <branch>` then `gh issue develop <id> --checkout`

If on `main` without an issue ID:
- Run `gh label list --json name` — user picks label and provides description
- Derive branch as `<label>/<description-kebab-case>`, confirm with user
- Run `git checkout -b <branch>`

Skip if already on a feature branch.

### 2. Code review gate

Invoke the `rust-code-reviewer` agent on the staged diff.
- **critical** and **improvement** issues block — do not proceed until resolved
- **learning** issues are shown but do not block

### 3. Commit

- Run `git diff --staged` to analyze changes
- Infer commit message following `CONTRIBUTING.md` format, confirm with user
- Run `git add -A && git commit -m "<message>"`

### 4. Push

Run `git push -u origin HEAD`.

### 5. Pull request

- Title: `<Type>: <Short Description>` from branch name
- Body: derived from `git diff main...HEAD` using `.github/PULL_REQUEST_TEMPLATE.md`
- No open PR: `gh pr create --title "<title>" --body "<body>" --draft --assignee "@me" --label "<branch-type>"`
- PR exists: `gh pr edit --body "<body>"`
