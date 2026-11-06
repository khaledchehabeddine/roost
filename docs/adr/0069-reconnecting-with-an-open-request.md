# Reconnecting With an Open Request

Acceptance and verification belong to the identity key, so they carry over to a session started from a contact's newer prekey bundle. When the contact's request is still open, that session's first message is a contact request, which accepts both sides as crossing requests do (ADR 0036). An acceptance counts only on the requester's session, which still points at the contact's old inbox.
