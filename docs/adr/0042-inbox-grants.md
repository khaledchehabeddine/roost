# Inbox Grants

A contact can deliver to an inbox only with its Discovery Key and Delivery Capability, so Roost builds, from SecureStorage, an Inbox Grant that carries both. The app never handles grants or its own capability, and sees a peer's capability only in an Established Message's destination, while a First Message routes by the recipient's prekeys.

## Alternatives

- Repeat only the capability on every Message: without its Discovery Key, Roost couldn't order it, and every Message would carry it forever.
- Send only the capability when the X3DH layer already carries the Discovery Key: two formats and two checks would save bytes the padding mostly hides.
- Let the app build grants: the app would hold its own capability, and each app would encode grants its own way.
