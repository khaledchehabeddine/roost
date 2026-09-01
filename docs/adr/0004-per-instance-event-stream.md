# Per-Instance Event Stream

**Status:** Accepted

State-change events are exposed through an in-process Event Stream scoped to one library instance, with Event IDs assigned at the same stream commit point that fixes the local state-change order. Each observer has an independent bounded buffer; slow observers receive an explicit lag signal with the number of missed events rather than silently losing events or blocking producers indefinitely. A current-state query returns a self-contained public snapshot tagged with the last reflected Event ID, so lagged observers can replace local state and resume after that tag without a gap or replay.

The stream is not a cross-instance delivery channel. After another library instance commits shared Protocol State Blobs, the host rebuilds public current state from those blobs under its protocol-state serializer and imports only that state into the local stream. Import advances a local State Revision, leaves the local Event ID unchanged, emits no Event, and gives existing observers a stale-state signal. Current State Snapshots carry both local tags and private stream provenance. An observer rejects a snapshot from another stream, a future local Event ID, or a revision that predates a later import. Generated bindings expose the snapshot as an opaque object so caller-controlled records cannot erase queued Events by copying another instance's numeric tags. A restarted stream reconstructs durable state with fresh local Event ID and State Revision sequences beginning at zero.

## Considered Options

- Global event stream over shared protocol state. Rejected. It would make this library responsible for cross-instance delivery and scheduling, conflicting with the consumer-owned protocol-state commit model.
- Importing another instance's Event IDs or re-emitting its changes as local Events. Rejected. Event IDs describe one producer's total order, while durable blobs hold cross-instance truth without an event history.
- Exposing Current State Snapshots as caller-constructible records. Rejected. Equal numeric tags from two streams could make an observer discard local Events while appearing to resume normally.
- Replacing current state silently. Rejected. Existing observers could keep a stale public view indefinitely with no recovery signal.
- Unbounded observer buffers. Rejected. A slow observer could grow memory without limit under externally driven traffic.
- Dropping oldest events without signaling. Rejected. Consumers would have no auditable way to know their local view had gaps.
