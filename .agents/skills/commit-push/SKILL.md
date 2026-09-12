---
name: commit-push
description: Commit and push the requested changes and create or update a draft PR. Not for cherry-picks, rebases, amends, or pushing without a commit.
---

# Commit and push

## Workflow

1. Read [CONTRIBUTING.md](../../../CONTRIBUTING.md) and [the tracker guide](../../../docs/agents/issue-tracker.md). Reuse the requested scope, branch and authorization; ask only when an unresolved choice materially changes the result.
2. Inspect `git status --short`, staged and unstaged diffs, and relevant untracked files. Select the authorized paths or hunks. Preserve unrelated work, including existing staged changes.
3. Use the task's existing branch when appropriate. For new work, fetch the target base and create `<type>/<short-description>` under the contributor conventions. Use an isolated worktree when unrelated checkout state would enter the PR. Resolve any supplied issue number through the tracker guide; tracker text stays out of shell strings.
4. Run the checks required by the change and dispatch applicable reviewers in parallel on the complete proposed diff:
   - `rust-code-reviewer` for Rust code changes.
   - `security-auditor` for crypto, protocol, identity or security-sensitive changes.
   - `api-reviewer` for cross-crate public API changes or changes under `crates/roost-client/`. Inspect changed methods, fields, variants and removals as well as declarations; a `pub` line grep cannot establish the scope.
   - Documentation and configuration changes use file validation and any checks their content requires.
   Resolve critical findings before committing. Apply authorized fixes and repeat only affected checks or reviews; ask the maintainer when resolution requires an unapproved decision. Advisory findings do not expand the task automatically.
5. Stage only the reviewed paths or hunks, then inspect `git diff --cached` and `git diff --cached --check`. The complete staged diff must match the reviewed scope, including new files. If unrelated changes are staged, isolate the task or separate the index entries while preserving their worktree contents and original staging state. Write the commit message through a non-shell filesystem API and run `git commit -F <message-path>` through an argv-safe process call. Commit only when the session authorizes it.
6. Push the authorized branch without force. Verify the destination is the repository specified by the tracker guide; leave tags and releases unchanged.
7. Inspect the full PR diff against its actual base, then create or update a draft through the tracker guide. Use [the PR template](../../../.github/PULL_REQUEST_TEMPLATE.md), a title describing the final change, the authorized label and assignee, and the footer below. Keep issue completion claims separate from PR creation. Check CI and address failures before reporting review completion.

Footer: `Created with [Codex](https://openai.com/codex).`
