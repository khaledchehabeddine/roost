# One Version per Encoding

Each sealed sender frame and protocol state blob starts with one version that covers every layer inside it, so readers never combine versions. A sender certificate is the one exception, because its domain signs it with its own version. Roost rejects an unknown version as an error and never resets or migrates the record silently.

## Alternatives

- A version on each layer: readers would have to handle combinations of versions.
- Reset a protocol state blob with an unknown version: the reset could put the ratchet, deduplication, acknowledgments, contacts, and the app's outbox out of step.
