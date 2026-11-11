# Holding the Identity Lock Through Each Commit

The app and its extensions share one identity lock. They hold it from each operation's first call until its commit resolves, and while finishing interrupted key changes, but never across a network call. Without it, an operation started during another process's reserved key change would fail, and finishing interrupted changes would abort that change.

## Alternatives

- Lock only key changes: a receive learns only partway through whether it uses up a one-time prekey.
- Hold the lock across a network call: nothing could be sent or received for the identity until the relay answered.
