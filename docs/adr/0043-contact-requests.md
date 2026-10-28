# Contact Requests

A contact becomes accepted only with both consents, the app's own request or acceptance and the peer's authenticated Message, where two requests that cross count as both. Who asked comes from who started the Session, and only a Contact Acceptance or the asked side's Inbox Grant on the requester's Session accepts (ADR 0086), because people may exchange a few Messages first.

## Alternatives

- Store who asked as its own Trust State: the Session a Message arrives on already says it.
- Treat any Message from the asked peer as acceptance: a reply sent for context would accept by accident.
