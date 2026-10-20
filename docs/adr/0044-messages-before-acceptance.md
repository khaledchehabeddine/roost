# Messages Before Acceptance

Before a contact is accepted, each side may send a few Messages so people can check who they're talking to, and one constant in Roost sets how many. Each side counts the distinct MessageIDs it sent to or received from that contact, refuses to send past the limit, and withholds the plaintext of Messages it receives past it. Sealed sender hides the sender from the Relay, so only the recipient can enforce a limit per sender.

## Alternatives

- One Message per request: someone who wants a little context first would have to accept a stranger to get it.
- Count both sides' Messages together: a lost or late Message would make the two sides disagree on when the limit applies.
- Count every send: resending a Message the Relay refused would use up the limit.
- Let the app pass the limit with each call: every send would take another setting, and two apps could disagree.
