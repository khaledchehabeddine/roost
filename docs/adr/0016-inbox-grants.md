# Inbox Grants

A contact can deliver to an inbox only with its discovery key and delivery capability, which an inbox grant carries. Roost builds each grant from SecureStorage, so the app never handles grants or its own capability. The app sees a peer's capability only in an established message's destination.

## Alternatives

- Let the app build grants: the app would hold its own capability, and each app would encode grants its own way.
- Repeat only the capability on every message: without its discovery key, Roost couldn't order it, and every message would carry it forever.
- Derive the capability from the discovery key: the capability must not be recoverable from public keys.
