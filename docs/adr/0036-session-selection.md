# Session Selection

Two peers can hold several Sessions with each other, such as when both start one at once, so Roost picks which one to send on and the app never does. As in Signal, each peer sends on the Session that most recently delivered a Message from the other, where starting or accepting a Session counts as its latest Message. When both peers start a Session at once, both begin with the one whose SessionID is lower, because otherwise each would switch to the other's and they would start crossed.

## Alternatives

- The lower SessionID always wins: a new Session replacing a Dead Session would lose half the time.
- Never send on the losing Session again: if the peers ever disagreed on which one lost, they would stay split instead of settling.
