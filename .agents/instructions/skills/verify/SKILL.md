# Verify

A change is done when evidence shows it works, not when it looks right. Evidence is a command's output or a reviewer's finding, never your own reading of the diff.

## Method

1. List what the task asked for and what would show each part is done.
2. Run `scripts/check.sh`, and fix each problem it prints until it ends with `All checks passed`, or its only failures are missed mutants you accept as [Roost Checks](#roost-checks) describes. While fixing, use the [Fast Loop](#fast-loop).
3. Compare the diff with the list from step 1, and with the `FEATURES.md` entries and ADRs it touches. Fix any part that solves a different problem or changes behavior the task didn't ask for.
4. Have a subagent that didn't write the change review it. Give it the task, the commit `scripts/check.sh` printed as the base, the untracked files the change adds, the skills that cover the changed files, such as `rust` and `writing`, and the [Known Gaps](#known-gaps) the change touches. Ask for each finding with its file, line, and a concrete way it fails. Fix or decline each finding, then have a reviewer check only those fixes.
5. Report the evidence in the [Report](#report) format.

When a check or finding still fails after three attempts, stop and report it as unverified, with what you tried.

### Fast Loop

- Run a failing test by name, such as `cargo test -p roost-core decode_example_rejects_unknown_version`, and run the script once it passes.
- Run `scripts/check.sh --no-mutants` while iterating, since mutation testing takes minutes. Run it without the flag before you report.
- Open a check's log in `target/check/` only when its printed lines don't explain the failure.

### Report

```markdown
- `scripts/check.sh`: <each check's pass, fail, or skip line>
- Review: <each finding and how you resolved it, or "no findings">
- Unverified: <each part no check or review covered, or "none">
```

## Roost Checks

`scripts/check.sh` runs only the checks the branch's changes need, and prints why it skips the rest.

- `fmt`, `clippy`, `test`, and `doc` match CI, and run unless only Markdown outside `crates/` changed. `test` and `doc` wait for `clippy` to pass.
- `deny` checks dependencies for security advisories and allowed licenses, and runs when a `Cargo.toml`, `Cargo.lock`, or `deny.toml` changes.
- `mutants` makes small edits to the source lines the branch changed, such as `*` to `+`, and runs the tests after each one. Each missed mutant is an edit no test noticed. Add a test that catches it when the [testing reference](../rust/references/testing.md) says the behavior needs one. Otherwise list it under Unverified, with the reason.

## Known Gaps

No check covers these, so the reviewer checks them by reading:

- Roost has no fuzz targets. Check each decoder of untrusted input against the Untrusted Input rules in the [cryptography reference](../rust/references/cryptography.md).
- No check compares the generated Swift and Kotlin bindings. When `roost-client`'s exports change, review them as the API the app calls.
