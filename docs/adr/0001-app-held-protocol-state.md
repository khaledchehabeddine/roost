# App-Held Protocol State

An app and its extensions may each run Roost for one identity, so the app stores all protocol state and passes its settings with each receive, and Roost keeps neither between operations. The app commits each operation's state updates and messages in one transaction, so a crash can't send a message without saving its state.

## Alternatives

- Keep protocol state in a long-lived object: the object and the app's database would both hold state, and a crash could leave them out of step.
- Let Roost commit through a storage callback: the app's transaction also covers its outbox and contact views, which Roost doesn't own.
