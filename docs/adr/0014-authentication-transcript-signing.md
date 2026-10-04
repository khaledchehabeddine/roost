# Authentication Transcript Signing

The app can ask Roost to sign its Relay authentication message with the Identity Key, unchanged, because the Relay expects its own format and a Roost prefix would make the signature fail. The app owns that message format, so Relay changes don't wait on Roost releases, and the identity secret never leaves Roost. This signer refuses any message that starts with the prefix Roost reserves for its own signatures, so the app can't use it to forge a Roost signature.

## Alternatives

- Accept only known Relay formats: each Relay change would need a Roost release.
