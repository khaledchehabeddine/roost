# Accepting on the Asked Side's Inbox Grant

A restore can lose a contact acceptance the requester received after its backup, and the asked side, already accepted, takes the requester's next request as an ordinary message. The asked side shares its inbox grant only when it accepts (ADR 0062), so its grant on the requester's session accepts as a contact acceptance does. A contact that starts a new session may have lost the grant along with its sessions, so it gets the grant again until it acknowledges one.

## Alternatives

- Leave it to recovery: recovery resends only unacknowledged messages, so an acceptance the requester acknowledged before restoring an older backup never comes back.
- Make the asked side's next message on the new session a contact acceptance: the requester would stay pending, under the limit on messages before acceptance, until the asked side wrote.
- Add an acknowledgment that says the contact is accepted: it would change the wire format to say what the grant already says.
