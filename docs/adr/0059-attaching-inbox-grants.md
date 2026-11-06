# Attaching Inbox Grants

Roost attaches its inbox grant to each message and acknowledgment for a contact until the contact acknowledges a message that carried it. It starts over after each recovery, because a contact that lost its session may have lost the grant too.

## Alternatives

- Send a grant only with the request and the acceptance: a lost or late acceptance would leave the requester under the limit on messages before acceptance until a retry.
- Leave grants off acknowledgments: a contact that starts a session from a prekey bundle learns the new discovery key without its capability, and couldn't send until the peer wrote.
- Keep a new session's handshake until the capability arrives: the contact would route by prekeys until the peer wrote, and the relay refuses those messages once the peer's signed prekey rotates.
- Leave the grant off recovered messages: a contact that lost its state couldn't reply.
