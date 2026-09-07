# Server

The Rust backend entry for stateless Evidence Bundle verification.

## Language

**Backend**:
The reporting consumer that supplies trusted domain keys, an expected Relay domain, and a trusted
Message acceptance time. It persists and deduplicates the verified Evidence Identity before
counting reports or performing downstream work. Verification creates no device or Session state.
Avoid: stateful Server, Client, transport

Evidence Bundle, Evidence Identity, Sender Certificate, and Message Transcript use the
[Protocol vocabulary](../roost-protocol/CONTEXT.md).
