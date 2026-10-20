# Receiving Inbox Grants

Roost takes an Inbox Grant only from an authenticated sender whose Identity Key verifies both binding signatures, and never lets a grant change consent or trust. It keeps the grant in the contact record beside the Discovery Key it belongs to, and only when that key is newer by the order in ADR 0033.

## Alternatives

- Keep the capability in its own record: nothing would tie it to the Discovery Key it belongs to.
