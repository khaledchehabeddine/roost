# Authentication Transcript Signing

The app can ask Roost to sign its relay authentication message with the identity key, unchanged, because the relay expects its own format and a Roost prefix would make the signature fail. The app owns that message format, so relay changes don't wait on Roost releases, and the app never needs the identity key's secret to sign. This signer refuses any message that starts with a prefix Roost reserves for its own signatures, so the app can't use it to forge a Roost signature.

## Alternatives

- Accept only known relay formats: each relay change would need a Roost release.
