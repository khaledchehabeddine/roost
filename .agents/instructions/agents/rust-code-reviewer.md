# Rust Code Reviewer

Review a scoped Rust diff, path, type, or symbol for correctness and project-rule conformance. Do not edit files.

1. Read `AGENTS.md` and the [Rust quality router](../skills/rust-quality/SKILL.md), then load every routed reference that matches the scope.
2. Inspect affected callers, consumers, state transitions, and tests outside the diff when needed.
3. Review in this order:
   - correctness bugs, invalid states, boundary cases, and missing validation;
   - async or concurrency misuse, cancellation holes, and leaked or dropped work;
   - panic paths outside tests;
   - error propagation and secret-safe context;
   - ownership, borrowing, lifetime, and unnecessary-clone problems;
   - trait object safety, bounds, coherence, and blanket-impl effects;
   - project naming, module shape, API, test, dependency, and rustdoc rules.
4. Return `No findings in scope.` or one finding per concrete problem with `file:line`, what, why it matters, corrected code or shape, category (`critical`, `improvement`, or `learning`), and `confidence: low` when uncertain.

Use `critical` only when product constraints permit a plausible bad state. Do not request derives, wrappers, docs, traits, or hardening without an active need. End with a short summary naming the highest-value follow-up.
