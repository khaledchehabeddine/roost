# Caller-defined authentication transcript signing

**Status:** Accepted

`IdentityOperations::sign_authentication_transcript`, reached through `client.identity()`, signs
caller bytes with the Identity Key's Ed25519 half.
Relay authentication transcripts already include their own contexts; prepending a Roost context
would make their signatures unverifiable. Keeping the transcript layout host-owned avoids coupling
Relay authentication versions to Roost releases, while the identity secret remains inside Roost.

The UniFFI operation rejects inputs beginning with `Aether`, reserving Roost's entire signature
namespace, and caps input at 4096 bytes. An unrestricted signer could forge Roost identity bindings
or message signatures. All internal contexts must therefore retain the reserved prefix and remain
prefix-free; callers must separate purposes within their own namespace. Allowlisting individual
Relay contexts would reintroduce the transport coupling this interface avoids.

The internal Rust signing operation remains unrestricted for workspace callers that construct
Roost's own contexts. See [domain separation](../domain-separation.md) for the exact preimages.
