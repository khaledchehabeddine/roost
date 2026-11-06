# Receiving Inbox Grants

Roost takes an inbox grant only from an authenticated sender whose identity key verifies both binding signatures. A grant accepts a contact only on the requester's session (ADR 0076), and never makes a contact verified. Roost keeps the grant in the contact record beside the discovery key it belongs to, and only when that key is newer by the order in ADR 0026 or is the stored key, which has no capability yet.

## Alternatives

- Keep the capability in its own record: nothing would tie it to the discovery key it belongs to.
