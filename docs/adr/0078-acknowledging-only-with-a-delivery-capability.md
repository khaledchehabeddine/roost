# Acknowledging Only With a Delivery Capability

A prekey bundle can show a contact's newer Discovery Key before any Inbox Grant for it arrives, such as when two requests cross after one side rotated, so a Message can arrive while this side can't reach the contact's inbox. Roost then delivers the Message without an acknowledgment, as a Requester does before acceptance (ADR 0065). The contact attaches its grant until this side acknowledges a Message that carried it, and a Recovery attaches it again (ADR 0059), so the capability arrives with the contact's next Message or resend.

## Alternatives

- Fail the receive until a grant arrives: a crossing request would fail on every retry, and an app that drops the failed Message would lose it.
- Queue the acknowledgment until a grant arrives: it would need new stored state and a new call to hand the app a late acknowledgment.
- Acknowledge to the older Discovery Key a stale grant names: the Relay drops Messages sent with an old capability once the new inbox is registered.
