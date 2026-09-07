# Standalone Binding Verification Over UniFFI

**Status:** Accepted

`verify_identity_key_binding` and `verify_discovery_to_identity_binding` are exported as two free
functions taking public material only, so a caller can check both halves of the mutual IK/DK binding
(AE-KEY-04) before any session or contact record exists. Both directions were already implemented
and correct in `roost-crypto`, but the only exported paths that reached them were `initiate_session`
— which needs a live publication bundle and a session — and `record_contact`, which covers IK→DK
alone. Adding a contact from a typed discovery key happens before either, so the check that decides
whether a relay-supplied identity is the one that discovery key vouches for had no Aether-side
answer, and the client wrote a second Ed25519 implementation of it.

## Considered Options

- One function taking a caller-chosen context. Rejected. `AetherIKBinding-v1:` and
  `AetherDKToIK-v1:` sign a **byte-identical** 64-byte payload, so the context is the only thing
  separating them. Letting the caller pass it moves that separation out of Aether and into the code
  most likely to get it wrong — which is the code this export exists to delete.
- One function verifying both directions at once. Rejected. A client applying an authenticated peer
  payload has the DK→IK signature but no self-binding signature to offer: the identity is already
  one Aether authenticated. Requiring both would force a placeholder at that call site.
- Return a boolean rather than `Result`. Rejected. A boolean that is ignored reads as success at
  every call site; a thrown `AetherError` aborts by default. `AuthenticationFailed` and `InvalidData`
  also keep "does not bind" distinguishable from "is not well formed", which a boolean collapses.
- Leave verification to the client and publish more vectors. Rejected. That is the state this
  replaces: correct Aether code, a hand-written translation beside it, and no `cargo test` that can
  see the two diverge.

## Consequences

- Neither function is a signing oracle — no secret key is involved — and neither is a general
  Ed25519 verification oracle. Each fixes its own context and rebuilds the payload from the identity
  key it was handed, so a caller chooses neither the context nor the shape of the signed bytes. The
  most either can answer is "is this a signature over `ik_x25519 || ik_ed25519` under this context",
  which is a public predicate anyone can already compute from `docs/domain-separation.md` and an
  off-the-shelf Ed25519 library. Nothing here can be pointed at `AetherDK-v1:`, `AetherSPK-v1:`,
  `AetherMessageTranscript-v1:`, or a sender certificate, because none of those payloads is
  constructible through these signatures.
- `roost_protocol::parse_ed25519_verifying_key_bytes` supplies shared canonical validation. A caller verifying a bare
  signature under a bare key has no bundle to parse the key for it, and `VerifyingKey::from_bytes`
  alone accepts non-canonical encodings and small-order points — a weak discovery key would report a
  binding that binds nothing. The strict parser every bundle constructor already uses is now
  reachable, so this export holds a relay-supplied key to the same standard.
- The DK→IK export takes an `IdentityKey` with no signature field, because that direction's payload
  is exactly the two identity halves. Internally it builds the bundle shape the core verifier takes
  with an all-zero signature that is never read, rather than accepting one it would silently ignore.
