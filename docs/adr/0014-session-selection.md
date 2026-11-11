# Session Selection

Two peers can hold several sessions with each other, so Roost picks which one to send on, and the app never does. As in Signal, each peer sends on the session that most recently delivered a message from the other, where starting or accepting a session counts as its latest message. When both peers start a session at once, both begin with the one whose session ID is lower, because otherwise each would switch to the other's and they would stay crossed.

## Alternatives

- The lower session ID always wins: a session started by recovery would lose half the time.
- Never send on the losing session again: if the peers ever disagreed on which one lost, they would stay split instead of settling.
