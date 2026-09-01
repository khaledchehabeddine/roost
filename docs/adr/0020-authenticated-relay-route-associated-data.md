# Authenticate Minimal Relay Route Metadata

**Status:** Accepted

Relay-facing operations authenticate a canonical `relay-route-v1` value as additional associated
data in the outer sealed-sender frame. The value contains only the Relay protocol version, route
kind, recipient Ed25519 signing key, and—for an X3DH initial—the stable unsigned 64-bit signed- and
one-time-prekey identifiers; this prevents a valid ciphertext from being rerouted across protocol
versions, recipients, or selected prekeys without making the cryptographic core responsible for
network routing or Relay admission policy.

## Considered Options

- Leave all route metadata outside authenticated encryption. Rejected because a Relay or transport
  intermediary could relabel an otherwise valid ciphertext for a different recipient or prekey
  lookup without an endpoint-authenticated failure.
- Authenticate the complete Relay request envelope. Rejected because delivery capabilities,
  authorization proofs, batching, and transport headers have independent lifecycles and remain
  caller-owned policy.
- Encode the route into every Message. Rejected because the Relay already carries these public
  fields and repeating them would expand the stable Message wire format; callers instead supply the
  same typed route on receive.

## Consequences

- A caller using a route-bound API must persist the exact route with an outbound Message and reuse
  it for retransmission; changing the protocol version changes the authenticated bytes.
- Relay admission proofs remain host-validated. Core admits a retained signed-prekey secret only
  after the caller supplies the route for an initial the Relay accepted before key supersession.
- Other routing data remains visible and unauthenticated by Aether.
