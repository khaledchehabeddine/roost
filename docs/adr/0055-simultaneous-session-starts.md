# Simultaneous Session Starts

When both peers start a Session at once, both begin with the one whose SessionID is lower, because otherwise each would switch to the other's and they would start crossed. A start on prekeys the peer has since rotated away doesn't count, since it can never complete.

## Alternatives

- Never send on the losing Session again: if the peers ever disagreed on which one lost, they would stay split instead of settling.
