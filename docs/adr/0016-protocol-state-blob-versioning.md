# Protocol State Blob Versioning

Each Protocol State Blob starts with a version that Core checks before decoding the rest, so Core can reject an unknown format before touching Session state. An unknown version is an error, never a reason to reset or migrate silently. Until a release promises that stored data survives upgrades, Core reads only the current format.

## Alternatives

- Let Crypto own the version: the blobs are Core's records, and Crypto owns only the ratchet data inside.
- Reset unknown blobs: a reset can put the ratchet, deduplication, acknowledgments, contacts, and the app's outbox out of sync.
