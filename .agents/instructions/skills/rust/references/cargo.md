# Cargo

- Inherit shared package metadata and lints from the [workspace manifest](../../../../../Cargo.toml). Add a key to `[workspace.package]` only when every crate takes the same value; keep crate-specific settings in the member manifest.
- Declare every external dependency's version and default features in `[workspace.dependencies]`, grouped with dependencies that must be bumped together. Inherit it only in crates that use it, and add crate-specific features there. Remove the workspace entry when no crate uses it.
- Use caret version requirements; the committed `Cargo.lock` keeps builds consistent. Pin exactly only with a comment explaining why.
- Prefer the standard library or an existing dependency when it meets the need.
- The [configured toolchain](../../../../../rust-toolchain.toml) is the only supported Rust version; don't add `rust-version`. When a dependency needs a newer Rust, bump the toolchain in a separate change first.
- Keep `cargo deny check advisories licenses sources` passing. CI runs it weekly, on dependency changes, and before signing mobile artifacts; run it locally after changing dependencies. Add a [`deny.toml`](../../../../../deny.toml) advisory ignore entry only with a comment naming the advisory and why it does not apply. Adding a license to the allow list is a legal decision; ask first.
- For dependency additions or updates, review maintenance status and added duplicate versions of transitive dependencies.
- Require established maintainers for dependencies handling keys, signatures, encryption, or key derivation. Prefer independently audited implementations. Check audit scope, findings, and subsequent changes. Explain missing coverage and the reason for choosing the dependency in the PR.
