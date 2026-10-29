# Verify

A change is done when evidence shows it works, not when it looks right. Evidence is a command's output or a reviewer's finding, never your own reading of the diff.

## Method

1. List what the task asked for and what would show each part is done.
2. Run each `cargo` step in the [CI workflow](../../../../.github/workflows/check.yml), with the `env` that step sets, and fix each problem until they all pass. Skip them when the change touches only Markdown outside `crates/`.
3. Have a subagent that didn't write the change review it against the list from step 1, and against the `FEATURES.md` entries and ADRs the change touches. Give it that list, the commit this task started from, which on a new branch is `git merge-base HEAD origin/main`, the untracked files the change adds, the skills that cover the changed files, such as `rust` and `writing`, and the [Known Gaps](#known-gaps) the change touches. Ask for each finding with its file, line, and a concrete way it fails. Fix or decline each finding, then have a reviewer check only those fixes.
4. Report the evidence in the [Report](#report) format.

When a check or finding still fails after three attempts, stop and report it as unverified, with what you tried.

### Report

```markdown
- Checks: <each command and whether it passed, or why you skipped them>
- Review: <each finding and how you resolved it, or "no findings">
- Unverified: <each part no check or review covered, or "none">
```

## Known Gaps

No check covers these, so the reviewer checks them by reading:

- Passing tests don't show that a test would fail if the new code broke. Check that each changed behavior has the test the [testing reference](../rust/references/testing.md) asks for.
- Roost has no fuzz targets. Check each decoder of untrusted input against the Untrusted Input rules in the [cryptography reference](../rust/references/cryptography.md).
- No check compares the generated Swift and Kotlin bindings. When `roost-client`'s exports change, check them against the [UniFFI reference](../rust/references/uniffi.md) and the Host API rules in the [documentation reference](../rust/references/documentation.md).
