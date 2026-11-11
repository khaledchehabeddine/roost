# Inbox Grants

An inbox grant carries the discovery key and delivery capability a contact needs to deliver to an inbox. Roost builds each grant from SecureStorage, so the app never handles grants or its own capability.

## Alternatives

- Let the app build grants: the app would hold its own capability, and each app would encode grants its own way.
- Derive the capability from the discovery key: anyone with the public keys could recover it.
