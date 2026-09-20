# API

- Keep modules private and re-export the crate's API from `lib.rs`; `unreachable_pub` flags `pub` items that aren't re-exported.
- Make an item `pub` only when code outside the crate uses it. Re-exporting it from `lib.rs` doesn't count as a use.
- Secret-bearing types additionally require a consumer who specifically needs the secret form
- Only `roost-client`'s UniFFI surface has a compatibility contract. Other crates' APIs may change freely inside the workspace.
- Describe every breaking change to that contract in the PR, with what hosts must change. In generated Swift and Kotlin, renaming or removing an item, field, or variant, adding an enum variant, and adding a required record field all break host code.
- Don't mark enums `#[non_exhaustive]`; every consumer is in this workspace. When matching an enum from another workspace crate, list every variant instead of `_`, so a new variant fails the build where it needs a decision.

## Errors

- Give each module or operation its own error enum with only the failures it can return, and wrap lower-level errors as variants. `ClientError` is the exception: it flattens everything into the one error Swift and Kotlin hosts catch.
