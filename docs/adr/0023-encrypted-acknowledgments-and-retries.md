# Encrypted Acknowledgments and Retries

An Acknowledgment Artifact is an encrypted Session Message that Core returns for the app to send, so servers in between can't see what was delivered. For unacknowledged Messages, Core returns Retry Instructions and the app does the resending.

## Alternatives

- Keep Pending Acknowledgments in memory: every Library Instance must see them, even after a restart.
