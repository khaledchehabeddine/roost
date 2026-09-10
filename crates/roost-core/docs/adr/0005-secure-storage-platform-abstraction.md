# Secure storage platform abstraction

**Status:** Accepted

Core owns the secure-storage trait because it owns identity persistence. The host supplies an
implementation at runtime through UniFFI; Core shares it as a trait object without depending on
platform APIs. In-memory test storage exercises this contract without an OS secret store.

Each entry write must be durable and non-tearing. Cross-entry recovery belongs to
[prepared operations](../../../../docs/adr/0018-recoverable-prepared-keystore-operations.md);
platform secret storage does not supply a transaction spanning the host's protocol database.
