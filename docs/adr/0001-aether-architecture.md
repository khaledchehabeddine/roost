# Aether Architecture

**Status:** Accepted

Aether is implemented in Rust because its ownership rules eliminate data races and use-after-free at compile time without runtime cost. It is exposed to client platforms via UniFFI because a single Rust implementation removes the platform-specific divergence that handwritten FFI would invite. The codebase is structured as a `crates/` workspace because the compiler-enforced layer boundary keeps each domain independently auditable, with `cargo check` enforcing acyclic dependencies without any tooling beyond the standard toolchain.
