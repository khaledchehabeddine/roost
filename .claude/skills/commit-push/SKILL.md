---
name: commit-push
description: Stage, commit, push, and create or update a pull request
argument-hint: [issue-id]
disable-model-invocation: true
allowed-tools: Bash(gh *) Bash(git *) Read
---

## Context

- Current branch: !`git branch --show-current`
- Current status: !`git status`
- Staged diff: !`git diff --staged`
- Diff against main: !`git diff main...HEAD`

## Task

### 1. Branch check

Skip if not on `main`.

If on `main` with `$ARGUMENTS`:
- `gh issue view $ARGUMENTS --json number,title,labels`
- Branch as `<label>/<issue-title-kebab-case>`, confirm with user
- `git checkout -b <branch>` then `gh issue develop $ARGUMENTS --checkout`

If on `main` without `$ARGUMENTS`:
- `gh label list --json name` — user picks label and provides description
- Branch as `<label>/<description-kebab-case>`, confirm with user
- `git checkout -b <branch>`

### 2. Code review gate

- Invoke `rust-code-reviewer` agent on the staged diff
- If the staged diff touches files under `crates/hermes-crypto/` or `crates/hermes-core/`, also invoke `security-auditor` agent on the staged diff
- **critical** and **improvement** issues from either agent block the commit — do not proceed until the user confirms resolution
- **learning** issues are shown but do not block

### 3. Commit

- Infer commit message from staged diff following `CONTRIBUTING.md` format, confirm with user
- `git add -A && git commit -m "<message>"`

### 4. Push

- `git push -u origin HEAD`

### 5. Pull request

- Title: `<Type>: <Short Description>` derived from branch name
- Body: derived from diff against main using `PULL_REQUEST_TEMPLATE.md` structure
- No open PR: `gh pr create --title "<title>" --body "<body>" --draft --assignee "@me" --label "<branch-type>"`
- PR exists: `gh pr edit --body "<body>"`
