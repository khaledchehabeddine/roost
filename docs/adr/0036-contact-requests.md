# Contact Requests

A contact becomes accepted only with both consents, the app's own request or acceptance and the peer's authenticated Message, where two requests that cross count as both. Who asked comes from who started the Session, and only a Contact Acceptance or the Asked Side's Inbox Grant on the Requester's Session accepts (ADR 0076), because people may exchange a few Messages first. The exception is a Message that starts a Session from a Requester's newer prekey bundle, which accepts even when it's an ordinary one, because no acceptance can reach the Requester's old Session (ADR 0069).

## Alternatives

- Store who asked as its own Trust State: the Session a Message arrives on already says it.
- Treat any Message from the asked peer as acceptance: a reply sent for context would accept by accident.
