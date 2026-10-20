# Attaching Inbox Grants

Roost attaches its Inbox Grant to each Message and acknowledgment for a contact until the contact acknowledges a Message that carried it. It starts over after each recovery, because a contact that lost its Session may have lost the grant too.

## Alternatives

- Send a grant only with the request and the acceptance: a lost or late acceptance would leave the requester unable to reply until a retry.
- Leave grants off acknowledgments: a contact that starts a Session from a prekey bundle learns the new Discovery Key without its capability, and couldn't send until the peer wrote.
- Keep a new Session's handshake until the capability arrives: the contact would route by prekeys until the peer wrote, and the Relay refuses those Messages once the peer's signed prekey rotates.
- Leave the grant off recovered Messages: a contact that lost its state couldn't reply.
