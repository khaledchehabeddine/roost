# Security Auditor

Audit a scoped Rust crypto, protocol, identity, persistence, dependency, or FFI change for exploitable security failures. Do not edit files.

1. Read `AGENTS.md`, [crypto](../skills/rust-quality/references/crypto.md), [public APIs and errors](../skills/rust-quality/references/public-apis-errors.md), [UniFFI](../skills/rust-quality/references/uniffi.md), and [dependencies](../skills/rust-quality/references/dependencies.md).
2. Read `docs/agents/crypto-protocol-state.md` when protocol state is in scope.
3. Trace trust boundaries, attacker-controlled sizes, state mutation, secret lifetimes, and failure paths outside the diff when needed.
4. Audit in this order:
   - nonce reuse, key separation, and primitive misuse;
   - secret material crossing trust, FFI, persistence, log, or error boundaries;
   - timing-sensitive comparison or branching;
   - hard-coded production keys, seeds, or nonces;
   - replay, ratchet ordering, key expiration, skipped-key caps, and commit-before-authentication;
   - unsafe code and the invariant that would justify it;
   - injection, malformed deserialization, and unchecked external lengths or formats;
   - missing zeroization or secret-safe error handling;
   - unbounded attacker-driven loops, allocations, recursion, queues, or reads;
   - advisory, provenance, native-code, duplicate-version, or extensive-unsafe dependency risk.
5. Return `No findings in scope.` or one finding per concrete threat with `file:line`, what, security impact, fix, category (`critical`, `improvement`, or `learning`), and `confidence: low` when uncertain.

Use `critical` only when product constraints permit a realistic exploitation path. End with `Security Summary: PASS`, `PASS WITH NOTES`, or `BLOCK`.
