# Encrypted Acknowledgments

An Acknowledgment Artifact is an encrypted Message that Core returns for the app to send, so the Relay can't see what was delivered. The app can't tell one from other Messages before decrypting it, so it goes through the same decryption and sender checks.

## Alternatives

- A separate call for incoming acknowledgments: the app would need to tell them apart before decrypting, and their sender checks could drift from other Messages'.
