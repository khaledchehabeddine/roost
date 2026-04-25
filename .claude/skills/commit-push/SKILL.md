---
name: commit-push
description: Stage, commit, push, and create or update a pull request
argument-hint: [issue-number]
disable-model-invocation: true
allowed-tools: Agent Bash(gh *) Bash(git *) Read
---

Commit and push changes:
1. Fetch pending changes: `git diff HEAD`.
2. Branch check:
   - Run `git branch --show-current`. Skip the rest of this step if not on `main`.
   - With `$ARGUMENTS`: `gh issue view $ARGUMENTS --json number,title,labels`, propose `<label>/<issue-title-kebab-case>`, confirm with the user, then `git checkout -b <branch>` and `gh issue develop $ARGUMENTS --checkout`.
   - Without `$ARGUMENTS`: `gh label list --json name`, ask the user to pick a label and provide a description, propose `<label>/<description-kebab-case>`, confirm with the user, then `git checkout -b <branch>`.
3. AI review gate:
   - Dispatch `rust-code-reviewer` and `security-auditor` in parallel — one message, two `Agent` calls — with the pending diff in each prompt.
   - `critical` findings block — surface the finding and proposed fix; do not proceed until the user confirms resolution.
   - `improvement` and `learning` findings are shown but do not block.
4. Confirm with the user they reviewed the diff.
5. Commit:
   - Compose a message from the pending diff following [CONTRIBUTING.md](../../../CONTRIBUTING.md) format, confirm with the user.
   - `git add -A && git commit -m "<message>"`.
6. `git push -u origin HEAD`.
7. Pull request:
   - Fetch the full diff: `git diff main...HEAD`.
   - Fill the body using [.github/PULL_REQUEST_TEMPLATE.md](../../../.github/PULL_REQUEST_TEMPLATE.md) structure.
   - Footer link: `[Claude Code](https://claude.com/claude-code)`.
   - Title: `<Label>: <Short Description>` from step 2, title-cased.
   - No open PR: `gh pr create --title "<title>" --body "<body>" --draft --assignee "@me" --label "<label>"`.
   - PR exists: `gh pr edit --body "<body>"`.
