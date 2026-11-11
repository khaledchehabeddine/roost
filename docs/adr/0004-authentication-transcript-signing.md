# Authentication Transcript Signing

The app can ask Roost to sign its relay authentication message with the identity key, so the app never holds the key's secret. Roost signs the message unchanged, because the relay expects its own format. It refuses any message that starts with a prefix Roost reserves for its own signatures, so the app can't use it to forge a Roost signature.

## Alternatives

- Accept only known relay formats: each relay change would need a Roost release.
