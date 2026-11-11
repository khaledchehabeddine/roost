# One Version per Encoding

Each sealed sender frame and protocol state blob starts with one version that covers every layer inside it, except a sender certificate, which its domain versions and signs. Roost rejects an unknown version as an error and never resets or migrates the record silently.

## Alternatives

- A version on each layer: readers would have to handle combinations of versions.
- Reset a blob with an unknown version: the reset could put sessions, contacts, and the app's outbox out of step.
