# App-owned observation of committed state

**Status:** Accepted for v0.16.0, superseding the per-instance Event Stream decision

The approved architecture resolution in [#259](https://github.com/RelayNet/roost/issues/259#issuecomment-5558392822)
removes Rust subscriptions, observer buffers, cursors, lag counts, and snapshot-resume handling.
Hosts observe their committed stores through platform facilities and ask Core to derive public
contact state from committed opaque blobs. No Rust instance owns authoritative observed state.

Typed operation results retain immutable change data, acknowledgments, evidence, and recovery
signals. The host commits those effects atomically with Core's conditional state updates before
displaying plaintext, transmitting Messages, or scheduling recovery. Once-only Session recovery
reporting is durable protocol state, independent of UI observation.

The trade-off is that platform observation may coalesce intermediate changes. Required effects
therefore follow operation results and durable commits. A replacement cursor framework would add
lifetime and synchronization work without improving that transaction contract.

`two_instance_integration.rs` verifies that an app can reconstruct public contact state after an
extension commits shared blobs. No per-instance event delivery guarantee remains in v0.16.0.
