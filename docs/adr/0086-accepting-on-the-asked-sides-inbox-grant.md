# Accepting on the Asked Side's Inbox Grant

A restore can lose a Contact Acceptance the requester received after its backup, and the asked side, already accepted, takes the requester's next request as an ordinary Message. The asked side shares its Inbox Grant only when it accepts (ADR 0071), so its grant on the requester's Session accepts as a Contact Acceptance does. A contact that starts a new Session may have lost the grant along with its Sessions, so it gets the grant again until it acknowledges one.

## Alternatives

- Leave it to recovery: recovery resends only unacknowledged Messages, so an acceptance the requester acknowledged before restoring an older backup never comes back.
- Make the asked side's next Message on the new Session a Contact Acceptance: the requester would stay Pending, under the limit on Messages before acceptance, until the asked side wrote.
- Add an acknowledgment that says the contact is accepted: it would change the wire format to say what the grant already says.
