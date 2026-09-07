---
name: commit-push
description: Trigger when the user wants to commit and push their current changes, or open a draft PR. Not for cherry-picks, rebases, amends, or pushing without a commit.
---

# Commit and Push

## Workflow

1. Load conventions: read [CONTRIBUTING.md](../../../CONTRIBUTING.md) for branch and commit format
2. Fetch pending changes: `git diff HEAD`
3. Branch check: run `git branch --show-current`. If the branch already follows the format, skip. Otherwise, create a feature branch:
   - With an issue ID:
     - Run `gh issue view <id> --json number,title,labels`
     - Derive branch as `<label>/<issue-title-kebab-case>`, confirm with the user
     - Run `gh issue develop <id> --name <branch> --checkout`
   - Without an issue ID:
     - Run `gh label list --json name`
     - Ask the user to pick a label and provide a description
     - Derive branch as `<label>/<description-kebab-case>`, confirm with the user
     - Run `git checkout -b <branch>`
4. AI review gate:
   - Invoke `rust-code-reviewer` and `security-auditor` in parallel on the pending diff
   - Also invoke `api-reviewer` in the same parallel batch when either holds:
     - A new cross-crate public item is added or modified: `git diff HEAD | grep -E '^\+pub [a-z]'` returns output
     - The diff touches `crates/roost-client/**`
   - Findings handling:
     - `critical` findings block — surface the finding and proposed fix; do not proceed until the user confirms resolution
     - `improvement` and `learning` findings are advisory
5. Commit:
   - Compose a message from the pending diff per the format, confirm with the user
   - Run `git add -A && git commit -m "<message>"`
6. Push: `git push -u origin HEAD`
7. Pull request:
   - Fetch the full diff: `git diff main...HEAD`
   - Fill the body using [.github/PULL_REQUEST_TEMPLATE.md](../../../.github/PULL_REQUEST_TEMPLATE.md)
   - Title: from step 3 branch — `/` → `: `, `-` → space, title-case (e.g., `feature/signed-prekey-rotation` → `Feature: Signed Prekey Rotation`)
   - Footer link: `[Codex](https://openai.com/codex)`
   - No open PR: `gh pr create --title "<title>" --body "<body>" --draft --assignee "@me" --label "<label>"`
   - PR exists: `gh pr edit --body "<body>"`
