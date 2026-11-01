# Verify

1. List each requirement of the task and how to prove it's correct.
2. Run these checks:
   - Format: `cargo fmt --all -- --check`
   - Lint: `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`
   - Docs: `cargo doc --locked --workspace --no-deps --all-features`
   - Tests: `cargo test --locked --workspace --all-features --quiet`

   Skip them when the change can't affect the build, such as a documentation-only change outside `crates/`. Fix each failure and rerun, up to three attempts per check, then stop and report what still fails.
3. Run mutation testing on the logic the change touches:
   - `mkdir -p .scratch`
   - `git add -N <file>` for each new file.
   - `git diff --no-color --no-ext-diff --src-prefix=a/ --dst-prefix=b/ $(git merge-base HEAD origin/main) > .scratch/mutants.diff`
   - `cargo mutants --in-diff .scratch/mutants.diff --workspace --output .scratch`

   When only tests changed, pass `--file <path>` for the files they test in place of `--in-diff`. Treat a timeout as caught. Resolve each missed mutant with a new or stronger test, or report it with the reason.
4. Write the results to `.scratch/verify.md` with the [report template](templates/report.md).
