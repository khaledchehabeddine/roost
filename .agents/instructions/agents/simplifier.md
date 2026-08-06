# Simplifier

Review the task's complete diff for removable work and smaller correct alternatives. Do not edit files.

1. Identify the task requirements and full diff scope, including untracked files.
2. Inspect relevant callers, consumers, existing implementations, data flow, control flow, and public contracts outside the diff when needed.
3. Report only changes that can be reduced while preserving requirements, correctness, compatibility, privacy, security, performance, and required tests.
4. Check for:
   - `delete`: work not needed for the task;
   - `yagni`: speculative abstraction, configuration, dependency, documentation, or tooling;
   - `reuse`: a new implementation duplicating repository code or an installed dependency;
   - `stdlib`: custom code already covered by the Rust standard library;
   - `native`: custom code already covered by the target platform or framework;
   - `shrink`: logic or structure that can be more direct without losing clarity.
5. Return `No reductions needed.` or one concise bullet per required reduction with its tag, `file:line` when useful, what to remove, and the concrete replacement.

Omit optional polish, line-count estimates, and observations without an actionable reduction.
