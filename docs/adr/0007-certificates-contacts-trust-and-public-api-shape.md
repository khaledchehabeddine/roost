# Contact trust and blocking

**Status:** Accepted, amended for v0.16.0

Certificate validity, local Trust State, and Blocking answer different questions. A domain-signed
certificate authenticates an Identity Key at a Relay; it does not confer local trust. Trust and
blocking share one IK-keyed Contact State Blob so they commit atomically and survive Discovery Key
rotation. Pending contacts become Unverified on acceptance and Verified only after out-of-band
Safety Number confirmation. In-band messages cannot raise trust to Verified.

Contact updates verify the IK-signed Discovery Key and accept only a newer `(created_at, epoch)`
pair, ordered timestamp first. Epochs cannot order independently restored storage lineages; the
signed timestamp can. The trade-off is that a legitimate rotation under a backward-moving clock
remains stale until a later rotation passes the stored timestamp.

Blocked messages still authenticate and advance receive state while withholding plaintext.
The default Unreachable policy suppresses acknowledgments and leaves the sending chain unchanged;
SilentReceipt reveals delivery by returning an acknowledgment. Duplicate messages do not generate
another acknowledgment. Certificate revocation rejects before the local blocking decision.

Generic certificate validation leaves grace policy to the caller, including an unlimited value.
The [evidence profile](0019-versioned-message-evidence-bundles.md) separately caps grace at 300
seconds. Certificate encodings and Safety Number derivation are specified in
[domain separation](../domain-separation.md); committed-state observation follows
[ADR 0004](0004-per-instance-event-stream.md).
