# Single-Use Message Operations

A Message Operation returns its result once and then refuses every call, and any error ends it too, because wrong input from the app is a bug that retrying won't fix, and keeping a result to return again would hold plaintext longer. Asking a waiting operation for its next step returns the same request without repeating cryptography, and calls from two threads take turns, so misuse gives the same result on every run. Dropping an operation erases its secrets but never commits or aborts anything, because a drop says nothing about whether the app's commit happened.

## Alternatives

- Return the result again when asked: Roost would keep plaintext in memory until the app dropped the operation.
- Let the app retry after wrong input: it adds a state for bugs that retrying rarely fixes.
- Fail a call that arrives while another is running: the failure would depend on timing, and it would end the first caller's operation.
