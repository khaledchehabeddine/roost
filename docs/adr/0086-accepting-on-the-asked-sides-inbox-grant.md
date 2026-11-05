# Accepting on the Asked Side's Inbox Grant

A restore can lose a Contact Acceptance the Requester received after its backup, and the Asked Side, already accepted, takes the Requester's next request as an ordinary Message. The Asked Side shares its Inbox Grant only when it accepts (ADR 0071), so its grant on the Requester's Session accepts as a Contact Acceptance does. A contact that starts a new Session may have lost the grant along with its Sessions, so it gets the grant again until it acknowledges one.

## Alternatives

- Leave it to Recovery: Recovery resends only unacknowledged Messages, so an acceptance the Requester acknowledged before restoring an older backup never comes back.
- Make the Asked Side's next Message on the new Session a Contact Acceptance: the Requester would stay Pending, under the limit on Messages before acceptance, until the Asked Side wrote.
- Add an acknowledgment that says the contact is accepted: it would change the wire format to say what the grant already says.
