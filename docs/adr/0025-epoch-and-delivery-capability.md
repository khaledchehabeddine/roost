# Epoch and Delivery Capability

The Discovery Key's Epoch also numbers the inbox, and the Delivery Capability is saved with the Discovery Key, so one write updates both. Two separate counters could disagree, and since blocking works by rotating the inbox, a blocked contact could keep delivering. Roost creates the capability and its verifier and sends the capability only inside Inbox Grants, but never registers or checks either.

## Alternatives

- Count inbox rotations apart from the Epoch: the Relay sees only one number, and merging the two later would need a live migration.
- Derive the capability from the Discovery Key: the capability must not be recoverable from public keys and must rotate on its own.
