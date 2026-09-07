# Received Message Deduplication API

**Status:** Accepted

Inbound encrypted Messages are received through a Core API that takes both the Session state key and
the local Identity's deduplication-state key, returning either an accepted plaintext result or a
duplicate outcome. The two keys are separate because ratchet/session state is scoped to a Session,
while the deduplication digest key and sliding window are scoped to the receiving Identity. A
duplicate is a normal receive result rather than an error: the consumer should not surface a user
visible effect, retry failure, or new protocol fault when byte-identical encrypted bytes arrive
again.

The API requires the consumer to initialize and persist the deduplication-set Protocol State Blob
for each local Identity. Core loads that blob at the start of receive, checks the digest before
ratchet decryption, and returns the advanced deduplication blob together with the advanced
ratchet/session blob only after the Message is accepted.

## Considered Options

- Reuse the Session key for deduplication. Rejected because it would scope the digest key and window
  to one Session rather than one receiving Identity.
- Return duplicates as errors. Rejected because duplicate transport delivery is an expected receive
  condition, not an operator fault or decrypt failure.
- Keep the old decrypt-only API alongside a deduplicating API. Rejected because it would leave a
  public bypass for the pre-decryption deduplication contract.
