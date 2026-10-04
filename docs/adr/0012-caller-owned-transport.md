# Caller-Owned Transport

Each app has its own delivery, push, and retry policy, so Roost does no networking. Roost returns Messages and acknowledgments as opaque bytes, and the app sends them however it chooses, with its own authentication, retries, and rate limits.

## Alternatives

- A standard transport envelope: apps need different metadata and versions.
- Treat transport authentication as proof of the sender: it proves only the app's channel, while X3DH, certificates, and signed transcripts prove the sender.
