# Reconnecting With an Open Request

Acceptance and verification belong to the Identity Key, so they carry over to a Session started from a contact's newer prekey bundle. When the contact's request is still open, that Session's first Message is a Contact Request, which accepts both sides as crossing requests do (ADR 0036). An acceptance counts only on the Requester's Session, which still points at the contact's old inbox.
