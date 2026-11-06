# Epoch and Delivery Capability

The discovery key's epoch also numbers the inbox, and the delivery capability is saved with the discovery key, so one write updates both. Two separate counters could disagree, and since blocking works by rotating the inbox, a blocked contact could keep delivering. Roost creates the capability and its verifier and sends the capability only inside inbox grants, but never registers or checks either.

## Alternatives

- Count inbox rotations apart from the epoch: the relay sees only one number, and merging the two later would need a live migration.
- Derive the capability from the discovery key: the capability must not be recoverable from public keys.
