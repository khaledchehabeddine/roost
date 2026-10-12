# Encrypted Acknowledgments and Retries

An Acknowledgment Artifact is an encrypted Session Message that Core returns for the app to send, so servers in between can't see what was delivered, and for unacknowledged Messages Core returns Retry Instructions and the app does the resending. The app can't tell an incoming acknowledgment from other Messages before decrypting it, so acknowledgments go through the same decryption and sender checks. Core picks where its own acknowledgment goes only after it authenticates the sender and applies block policy, then asks the app for that destination's Transport Binding, because the route the incoming Message arrived on may not reach the sender.

## Alternatives

- Keep Pending Acknowledgments in memory: every Library Instance must see them, even after a restart.
- A separate call for incoming acknowledgments: the app would need to tell them apart before decrypting, and their sender checks could drift from other Messages'.
- Let the app pick the acknowledgment's destination up front: it would choose before Roost knows who sent the Message or whether they're blocked.
