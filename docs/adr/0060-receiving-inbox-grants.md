# Receiving Inbox Grants

Roost takes an Inbox Grant only from an authenticated sender whose Identity Key verifies both binding signatures. A grant accepts a contact only on the Requester's Session (ADR 0076), and never makes a contact verified. Roost keeps the grant in the contact record beside the Discovery Key it belongs to, and only when that key is newer by the order in ADR 0026 or is the stored key, which has no capability yet.

## Alternatives

- Keep the capability in its own record: nothing would tie it to the Discovery Key it belongs to.
