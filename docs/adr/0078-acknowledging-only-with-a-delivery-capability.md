# Acknowledging Only With a Delivery Capability

A prekey bundle can show a contact's newer discovery key before any inbox grant for it arrives, such as when two requests cross after one side rotated, so a message can arrive while this side can't reach the contact's inbox. Roost then delivers the message without an acknowledgment, as a requester does before acceptance (ADR 0065). The contact attaches its grant until this side acknowledges a message that carried it, and a recovery attaches it again (ADR 0059), so the capability arrives with the contact's next message or resend.

## Alternatives

- Fail the receive until a grant arrives: a crossing request would fail on every retry, and an app that drops the failed message would lose it.
- Queue the acknowledgment until a grant arrives: it would need new stored state and a new call to hand the app a late acknowledgment.
- Acknowledge to the older discovery key a stale grant names: the relay drops messages sent with an old capability once the new inbox is registered.
