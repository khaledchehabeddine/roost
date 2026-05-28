# Aether Engine Architecture

**Status:** Accepted

Aether is implemented in Rust and exposed to client platforms via UniFFI, structured as a `crates/` workspace with a strict layered dependency graph. One implementation eliminates platform-specific divergence in transport and cryptographic behavior; ownership rules eliminate data races and use-after-free at compile time without runtime cost; the workspace boundary makes each concern independently auditable, with the compiler enforcing acyclic dependencies.
