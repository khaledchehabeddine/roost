---
description: Stage, commit, push, and create or update a pull request
argument-hint: [issue-number]
disable-model-invocation: true
allowed-tools: Agent Bash(gh *) Bash(git *) Read
---

When committing and pushing changes:

1. **Load conventions**: read [CONTRIBUTING.md](../../../CONTRIBUTING.md) for branch and commit format
2. **Fetch pending changes**: `git diff HEAD`
3. **Branch check**: run `git branch --show-current`. If the branch already follows the format, skip. Otherwise, create a feature branch:
   - With `$ARGUMENTS`:
     - `gh issue view $ARGUMENTS --json number,title,labels`
     - Propose `<label>/<issue-title-kebab-case>`, confirm with the user
     - `gh issue develop $ARGUMENTS --name <branch> --checkout`
   - Without `$ARGUMENTS`:
     - `gh label list --json name`
     - Ask the user to pick a label and provide a description
     - Propose `<label>/<description-kebab-case>`, confirm with the user
     - `git checkout -b <branch>`
4. **AI review gate**:
   - Dispatch `rust-code-reviewer` and `security-auditor` in parallel — one message, two `Agent` calls — with the pending diff
   - Also dispatch `api-reviewer` in the same parallel batch when either holds:
     - A new cross-crate public item is added or modified: `git diff HEAD | grep -E '^\+pub [a-z]'` returns output
     - The diff touches `crates/aether-uniffi/**`
   - Findings handling:
     - `critical` findings block — surface the finding and proposed fix; do not proceed until the user confirms resolution
     - `improvement` and `learning` findings are advisory
5. **Commit**:
   - Compose a message from the pending diff per the format, confirm with the user
   - `git add -A && git commit -m "<message>"`
6. **Push**: `git push -u origin HEAD`
7. **Pull request**:
   - Fetch the full diff: `git diff main...HEAD`
   - Fill the body using [.github/PULL_REQUEST_TEMPLATE.md](../../../.github/PULL_REQUEST_TEMPLATE.md)
   - Title: from step 3 branch — `/` → `: `, `-` → space, title-case (e.g., `feature/ble-transport-retry` → `Feature: BLE Transport Retry`)
   - Footer link: `[Claude Code](https://claude.com/claude-code)`
   - No open PR: `gh pr create --title "<title>" --body "<body>" --draft --assignee "@me" --label "<label>"`
   - PR exists: `gh pr edit --body "<body>"`
