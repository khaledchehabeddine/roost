# Contact Requests

A contact becomes accepted only with both consents, the app's own request or acceptance and the peer's authenticated message, where two requests that cross count as both. Who asked comes from who started the session, and only a contact acceptance or the asked side's inbox grant on the requester's session accepts (ADR 0076), because people may exchange a few messages first. The exception is a message that starts a session from a requester's newer prekey bundle, which accepts even when it's an ordinary one, because no acceptance can reach the requester's old session (ADR 0069).

## Alternatives

- Store who asked as its own trust state: the session a message arrives on already says it.
- Treat any message from the asked peer as acceptance: a reply sent for context would accept by accident.
