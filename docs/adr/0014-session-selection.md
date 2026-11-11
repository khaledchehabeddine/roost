# Session Selection

Two peers can hold several sessions, and Roost, not the app, picks which one to send on. As in Signal, each peer sends on the session that most recently delivered a message from the other. When both start a session at once, both begin with the lower session ID, because otherwise each would switch to the other's and they would stay crossed.

## Alternatives

- The lower session ID always wins: a session started by recovery would lose half the time.
- Never send on the losing session again: peers that disagreed on which one lost would stay split.
