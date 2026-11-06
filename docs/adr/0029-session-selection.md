# Session Selection

Two peers can hold several sessions with each other, such as when both start one at once, so Roost picks which one to send on and the app never does. As in Signal, each peer sends on the session that most recently delivered a message from the other, where starting or accepting a session counts as its latest message, except when both peers start at once (ADR 0055).

## Alternatives

- The lower session ID always wins: a session started by recovery would lose half the time.
