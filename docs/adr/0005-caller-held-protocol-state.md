# Caller-Held Protocol State

An app and its extensions may each run a Library Instance for one Identity, so the app stores all protocol state as Protocol State Blobs and Roost keeps no copy between operations. Each operation returns its state updates together with its Messages and Events, and the app commits them in one transaction, so a crash can't send a Message without saving its state. Each update applies only if the stored blob hasn't changed since the operation read it, so two operations can't silently overwrite each other.

## Alternatives

- Keep protocol state in a long-lived UniFFI object: the object and the app's database would both hold state, and a crash could leave them out of step.
- Let Roost commit through a storage callback: the app's transaction also covers its outbox and contact views, which Roost doesn't own.
- Give Swift and Kotlin decoded state: apps would depend on internal formats and handle more secret data.
