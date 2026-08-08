# Commit and Push

This workflow may prepare and publish reviewed repository changes. Never merge or force-push.

## Inspect

1. Read `CONTRIBUTING.md` and `.github/PULL_REQUEST_TEMPLATE.md`.
2. Inspect all pending state before proposing any mutation:
   - `git status --short`.
   - `git diff --stat` and `git diff` for unstaged tracked changes.
   - `git diff --cached --stat` and `git diff --cached` for staged tracked changes.
   - `git ls-files --others --exclude-standard`, then read every untracked file in full with a non-executing local reader appropriate to its type.
3. Preserve unrelated user changes and exclude them from the plan. A clean worktree may still contain committed work to publish.
4. Run `git branch --show-current`; stop on detached `HEAD`. If a new branch is needed, derive a `CONTRIBUTING.md`-compliant name and confirm it before creation.

## Establish the review base

1. Identify the intended pull-request base from the current PR when one exists, remote branch relationships, and stacked branch ancestry. Do not assume `main`.
2. Explain the evidence for the proposed base and have the user confirm it. Stop if the base cannot be established.
3. Inspect the committed range and diff with `git log --oneline <confirmed-base>..HEAD`, `git diff --stat <confirmed-base>...HEAD`, and `git diff <confirmed-base>...HEAD`.
4. Stop only when both the pending state and committed diff against the confirmed base are empty.
5. Use the confirmed base for every diff, gate, and pull-request action.

## Gate and review

1. Run `scripts/check.sh full --base <confirmed-base>`. A quick gate never substitutes for this command.
2. Review the exact committed diff at `<confirmed-base>...HEAD` plus all pending staged, unstaged, and untracked changes.
3. Invoke the read-only `simplifier` for every diff.
4. Invoke scoped reviewers in the same reviewed state:
   - `rust-code-reviewer` for Rust source, manifests, Rust tests, generated-binding declarations, or Rust-facing tooling.
   - `security-auditor` for crypto, protocol state, identity, secret handling, unsafe or deserialization boundaries, security-sensitive dependencies, or security documentation.
   - `api-reviewer` for cross-crate public API or `crates/aether-uniffi/` changes.
5. Treat every concrete finding as blocking until fixed or explicitly waived by the user. Re-run affected gates and reviews after fixes.
6. Permit a correctness or security waiver only with explicit user approval and compensating evidence that addresses the stated failure or threat. Do not infer approval from silence.
7. Record evidence in the proposed PR body or handoff using this shape:

```text
Gate evidence
- base: <confirmed-base and rationale>
- full gate: <command and result>
- simplifier: <result>
- rust review: <result or not in scope>
- security review: <result or not in scope>
- API review: <result or not in scope>

Waivers
- <finding>: <user-approved rationale>; compensating evidence: <evidence or not applicable>
```

8. Re-inspect the committed range and base diff, status, staged and unstaged diffs, and every untracked file. If the reviewed content or confirmed base changed, stop and repeat the full gate and applicable reviews.

## Publish

1. If pending work exists, propose explicit file paths for staging. Require user confirmation specifically for staging, then stage only those paths.
2. If staged work exists, verify it matches the reviewed state, then propose commit grouping and messages. Require user confirmation specifically for the commit or commits, then create them.
3. Recompute the committed base diff plus pending state. Verify its content matches the reviewed change set and no unrelated change appeared; otherwise repeat the full gate and applicable reviews.
4. When the reviewed branch needs publishing, require user confirmation specifically for the push, then run `scripts/push-reviewed-branch.sh` without arguments. Clean reviewed commits do not require staging or commit confirmation before this separately confirmed push.
5. Build the title and body from the confirmed base diff and `.github/PULL_REQUEST_TEMPLATE.md`, including gate evidence and waivers. Pass the body directly or through an absolute, reviewed, regular non-symlink file inside the repository.
6. Check for an existing pull request. Require user confirmation specifically for creating a draft pull request or updating the existing pull request, then perform only the confirmed action against the confirmed base.
7. Return branch, commit, push, and pull-request results. Never mark a draft ready, merge, or force-push.
