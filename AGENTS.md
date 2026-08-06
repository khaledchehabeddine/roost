# Aether

Aether is the shared cryptographic and networking core for a private, end-to-end encrypted cloud messaging system. See [README.md](README.md#architecture) for crate ownership and dependencies.

## Project invariants

- Prioritize correctness, security, and auditability; then clarity and minimal design; then measured performance; raw reduction comes last.
- `aether-crypto` owns cryptographic primitives and protocol mechanics, `aether-core` owns entities and orchestration, and `aether-uniffi` owns platform adaptation. Hosts own network I/O, transport routing, transport-envelope authentication, durable persistence, and OS security integrations; Aether owns protocol identity binding and Message authenticity.
- Use Rust 1.95.0. Unsafe Rust is forbidden. Model every production failure path with `Result`; `unwrap()`, `expect()`, `panic!()`, `todo!()`, and `unimplemented!()` are forbidden outside tests.
- Use OS randomness, distinct non-empty HKDF domains, and HKDF-derived message nonces. Immediately zeroize heap and FFI secrets, compare secrets in constant time, cap attacker-controlled work, and keep CPU-bound crypto synchronous.
- Minimize public and FFI surfaces. Expose a secret-bearing form only to a consumer that specifically needs it, wrap FFI secret bytes immediately on the Rust side, and never put secrets in errors or logs.
- Keep tests deterministic and prove boundary contracts plus security and protocol invariants.
- Read the [Rust quality router](.agents/instructions/skills/rust-quality/SKILL.md) and only its matching references for detailed rules.

## Project instructions

- Keep canonical project skill and reviewer bodies in `.agents/instructions/`. Keep `.agents/skills/`, `.claude/skills/`, `.claude/rules/`, `.claude/agents/`, and `.codex/agents/` adapters as native metadata plus one route to a canonical target.
- Run agent shell searches as `rg --no-config`; the command boundary rejects user-configured preprocessing and helper execution.
- Keep collaborator-facing customization in this repository; use user scope only for preferences that neither shape project workflow nor improve collaborator results.
- Mirror discovery or invocation-policy changes across Claude and Codex adapters without copying canonical bodies. Follow the native shape of peer adapters.
- Keep skill metadata aligned with the canonical workflow and in the same trigger order. When `paths` gates loading, do not repeat that path filter in the description. Omit the project name from customization descriptions except in literal paths.
- For Rust implementation, review, tests, dependencies, public APIs, UniFFI, or rustdoc, follow the Rust quality route above.
- For terminology, context boundaries, context relationships, or architectural decisions, read [.agents/instructions/skills/domain-modeling/SKILL.md](.agents/instructions/skills/domain-modeling/SKILL.md).
- `CONTRIBUTING.md` governs every branch, commit, and pull-request convention.
- Stage, commit, push, or create or update a pull request only through explicit `commit-push` invocation and its action-specific confirmations.
- Never merge or force-push.
- After a non-obvious project-specific discovery or workaround worth preserving, propose the smallest canonical instruction update.
