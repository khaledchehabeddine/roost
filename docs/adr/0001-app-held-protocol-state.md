# App-Held Protocol State

An app and its extensions may each run Roost for one identity, so Roost keeps no state or settings between operations. The app stores all protocol state and commits each operation's updates and messages in one transaction, so a crash can't send a message without saving its state.

## Alternatives

- Keep state in a long-lived object: the object and the app's database could fall out of step after a crash.
- Commit through a storage callback: the app's transaction also covers its outbox and contact views, which Roost doesn't own.
