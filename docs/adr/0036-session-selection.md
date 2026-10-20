# Session Selection

Two peers can hold several Sessions with each other, such as when both start one at once, so Roost picks which one to send on and the app never does. As in Signal, each peer sends on the Session that most recently delivered a Message from the other, where starting or accepting a Session counts as its latest Message.

## Alternatives

- The lower SessionID always wins: a Session started by recovery would lose half the time.
