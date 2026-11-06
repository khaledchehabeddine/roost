# Inbox Grants

A contact can deliver to an inbox only with its discovery key and delivery capability, so Roost builds, from SecureStorage, an inbox grant that carries both. The app never handles grants or its own capability, and sees a peer's capability only in an established message's destination, while a first message routes by the recipient's prekeys.

## Alternatives

- Repeat only the capability on every message: without its discovery key, Roost couldn't order it, and every message would carry it forever.
- Send only the capability when the X3DH layer already carries the discovery key: two formats and two checks would save bytes the padding mostly hides.
- Let the app build grants: the app would hold its own capability, and each app would encode grants its own way.
