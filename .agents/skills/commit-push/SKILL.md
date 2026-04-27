---
name: commit-push
description: Trigger when the user wants to commit and push their current changes, or open a draft PR. Not for cherry-picks, rebases, amends, or pushing without a commit.
---

## Steps

### 1. Fetch pending changes

Run `git diff HEAD`.

### 2. Branch check

Run `git branch --show-current` and `git status`.

If on `main` with an issue ID provided:
- Run `gh issue view <id> --json number,title,labels`
- Derive branch as `<label>/<issue-title-kebab-case>`, confirm with user
- Run `gh issue develop <id> --name <branch> --checkout`

If on `main` without an issue ID:
- Run `gh label list --json name` — user picks label and provides description
- Derive branch as `<label>/<description-kebab-case>`, confirm with user
- Run `git checkout -b <branch>`

Skip if already on a feature branch.

### 3. AI review gate

Invoke the `rust-code-reviewer` and `security-auditor` agents in parallel on the pending diff.

If the diff touches `crates/*/src/lib.rs` or `crates/hermes-uniffi/**`, also invoke the `api-reviewer` agent in the same parallel batch.

- **critical** findings from any agent block — surface the finding and proposed fix; do not proceed until the user confirms resolution
- **improvement** and **learning** findings are shown but do not block

### 4. Confirm

Confirm with the user they reviewed the diff.

### 5. Commit

- Compose a message following [CONTRIBUTING.md](../../../CONTRIBUTING.md) format, confirm with user
- Run `git add -A && git commit -m "<message>"`

### 6. Push

Run `git push -u origin HEAD`.

### 7. Pull request

- Fetch the full diff: `git diff main...HEAD`
- Fill the body using [.github/PULL_REQUEST_TEMPLATE.md](../../../.github/PULL_REQUEST_TEMPLATE.md) structure
- Footer link: `[Codex](https://openai.com/codex)`
- Title: `<Label>: <Short Description>` from step 2, title-cased
- No open PR: `gh pr create --title "<title>" --body "<body>" --draft --label "<label>"`
- PR exists: `gh pr edit --body "<body>"`
