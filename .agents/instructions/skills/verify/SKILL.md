# Verify

1. List each requirement of the task and how to prove it's correct.
2. Run these checks, and rerun them after each fix:
   - Format: `cargo fmt --all -- --check`
   - Lint: `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`
   - Docs: `cargo doc --locked --workspace --no-deps --all-features`
   - Tests: `cargo test --locked --workspace --all-features --quiet`

   Skip them when the change can't affect the build.
3. Run mutation testing on this branch's changes:

   ```sh
   mkdir -p .scratch
   git ls-files -z --others --exclude-standard > .scratch/untracked
   xargs -0 -r git add -N -- < .scratch/untracked
   git diff --no-color --no-ext-diff --src-prefix=a/ --dst-prefix=b/ $(git merge-base HEAD origin/main) | cargo mutants --in-diff /dev/stdin --workspace --test-workspace=true --output .scratch
   xargs -0 -r git reset -q -- < .scratch/untracked
   ```

   When only tests changed, pass `--file <path>` for the files they test in place of `--in-diff`. Resolve each missed mutant with a new or stronger test, or report it with the reason. Rerun step 2 after adding tests. Report a timeout as caught, and a diff with no Rust source as Skipped.
4. Write the results to `.scratch/verify.md` in the form of the Verification section of the [PR template](../../../../.github/PULL_REQUEST_TEMPLATE.md).
