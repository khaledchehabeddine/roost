# Per-Instance Event Stream

**Status:** Accepted

State-change events are exposed through an in-process Event Stream scoped to one library instance, with Event IDs assigned at the same stream commit point that fixes the local state-change order. Each observer has an independent bounded buffer; slow observers receive an explicit lag signal with the number of missed events rather than silently losing events or blocking producers indefinitely. A current-state query returns a self-contained public snapshot tagged with the last reflected Event ID, so lagged observers can replace local state and resume after that tag without a gap or replay.

The stream is not a cross-instance delivery channel. Changes committed by another library instance are observed through the shared protocol-state store and any operation that imports those durable changes into the local instance's event-producing surface.

## Considered Options

- Global event stream over shared protocol state. Rejected. It would make this library responsible for cross-instance delivery and scheduling, conflicting with the consumer-owned protocol-state commit model.
- Unbounded observer buffers. Rejected. A slow observer could grow memory without limit under externally driven traffic.
- Dropping oldest events without signaling. Rejected. Consumers would have no auditable way to know their local view had gaps.
