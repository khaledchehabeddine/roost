# Messages Before Acceptance

Before a contact is accepted, each side may send a few messages so people can check who they're talking to, and Roost sets how many. Each side counts the distinct message IDs it sent to or received from that contact, refuses to send past the limit, and withholds the plaintext of messages it receives past it. Sealed sender hides the sender from the relay, so only the recipient can enforce a limit per sender.

## Alternatives

- One message per request: someone who wants a little context first would have to accept a stranger to get it.
- Count both sides' messages together: a lost or late message would make the two sides disagree on when the limit applies.
- Count every send: resending a message the relay refused would use up the limit.
- Let the app pass the limit with each call: every send would take another setting, and two apps could disagree.
