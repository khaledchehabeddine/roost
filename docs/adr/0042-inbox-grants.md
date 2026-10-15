# Inbox Grants

A contact can deliver to an inbox only with its Discovery Key and Delivery Capability, so Roost builds an Inbox Grant from SecureStorage and attaches it to each Message and acknowledgment for a contact until that contact acknowledges a Message that carried it, and the app never handles grants or its own capability. Roost takes a grant only from an authenticated sender whose Identity Key verifies both binding signatures, keeps it in the contact record beside the Discovery Key it belongs to when that key is newer by the order in ADR 0033, and never lets a grant change consent or trust. A peer's capability leaves Roost only in the destination of an established Message, while a first Message routes by the recipient's prekeys.

## Alternatives

- Send a grant only with the request and the acceptance: a lost or late acceptance would leave the requester unable to reply until a retry.
- Repeat only the capability on every Message: without its Discovery Key, Roost couldn't order it, and every Message would carry it forever.
- Send only the capability when the X3DH layer already carries the Discovery Key: two formats and two checks would save bytes the padding mostly hides.
- Keep the capability in its own record: nothing would tie it to the Discovery Key it belongs to.
- Let the app build grants: the app would hold its own capability, and each app would encode grants its own way.
- Leave grants off acknowledgments: a contact that starts a Session from a prekey bundle learns the new Discovery Key without its capability, and couldn't send until the peer wrote.
- Keep a new Session's handshake until the capability arrives: the contact would route by prekeys until the peer wrote, and the Relay refuses those Messages once the peer's signed prekey rotates.
