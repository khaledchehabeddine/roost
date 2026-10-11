# Standalone Binding Verification

Roost exports two verifiers so apps don't reimplement Ed25519 checks: one checks an Identity Key's self-signature, and one checks that a Discovery Key signed its Identity Key. Each verifier sets its own signature prefix instead of taking one from the app, because both signatures sign the same Identity Key bytes and only the prefix tells them apart. The two verifiers stay separate because an app doing discovery may hold a trusted Identity Key without its self-signature.
