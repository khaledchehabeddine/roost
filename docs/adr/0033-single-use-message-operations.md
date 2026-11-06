# Single-Use Message Operations

A message operation returns its result once and then refuses every call, and any error ends it too. Wrong input from the app is a bug that retrying won't fix, and keeping a result to return again would hold plaintext longer. Dropping an operation erases its secrets but never commits or aborts anything, because a drop says nothing about whether the app's commit happened.

## Alternatives

- Return the result again when asked: Roost would keep plaintext in memory until the app dropped the operation.
- Let the app retry after wrong input: it adds a state for bugs that retrying rarely fixes.
