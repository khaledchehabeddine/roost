# App-Held Protocol State

An app and its extensions may each run a library instance for one identity, so the app stores all protocol state as protocol state blobs and Roost keeps no copy between operations. Each operation returns its state updates with its messages and signals, and the app commits them in one transaction, so a crash can't send a message without saving its state.

## Alternatives

- Keep protocol state in a long-lived UniFFI object: the object and the app's database would both hold state, and a crash could leave them out of step.
- Let Roost commit through a storage callback: the app's transaction also covers its outbox and contact views, which Roost doesn't own.
- Give Swift and Kotlin decoded state: apps would depend on internal formats and handle more secret data.
