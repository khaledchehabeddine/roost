# Authentication Transcript Signing

Roost signs the app's relay authentication message with the identity key, unchanged, because the relay expects its own format. It refuses any message that starts with a prefix Roost reserves for its own signatures, so the app can't use it to forge one.

## Alternatives

- Accept only known relay formats: each relay change would need a Roost release.
