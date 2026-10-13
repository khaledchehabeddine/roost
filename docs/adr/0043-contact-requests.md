# Contact Requests

Roost creates a contact record only when someone sends a Contact Request, and a contact becomes accepted only with both consents, the app's own request or acceptance and the peer's authenticated Message, where two requests that cross count as both. Who asked comes from who started the Session a Message arrives on, and only a Contact Acceptance on the requester's Session accepts, because people may exchange a few Messages first, and the asked side shares its Inbox Grant only when it accepts, so a requester it turns down never holds its Delivery Capability. Blocking still rotates the inbox even for a stranger, because only a new address stops a blocked person from returning with a new identity, while deleting a request just hides it.

## Alternatives

- Record a contact when the app scans a link or looks one up: leaving without asking would still create a contact that Roost couldn't tell from one that asked.
- Store who asked as its own Trust State: the Session a Message arrives on already says it.
- Treat any Message from the asked peer as acceptance: a reply sent for context would accept by accident.
- Share the asked side's grant with its first reply: a stranger it then turned down would keep delivering until it rotated its inbox.
- Block a stranger's request without rotating the inbox: the stranger could return with a new identity at the same address.
