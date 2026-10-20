# Holding the Identity Lock Through Each Commit

The app and its extensions can each run Roost for one Identity, and a key change stays staged in SecureStorage until the app's commit resolves. So they share one Identity Lock, held from each operation's first call until its commit resolves and during recovery, but never across a network call. Any operation started during another process's staged change would fail, and recovering then would abort that change.

## Alternatives

- Lock only key changes and let other operations run at once: a receive learns partway through whether it uses up a one-time prekey, and other starts would fail during another process's commit.
