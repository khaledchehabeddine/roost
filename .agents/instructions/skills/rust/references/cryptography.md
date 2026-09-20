# Cryptography

- Use `OsRng` or `getrandom` directly for production randomness.
- Hardcoded secret keys, seeds, and nonces are restricted to test fixtures.
- Never expose secrets in errors, logs, or `Debug` output. Use non-secret identifiers for diagnostic context.
- Never reuse an AEAD key/nonce pair for a new encryption. Preserve the operation's nonce construction; consult its ADR before changing it.
- Use stable domain-separation labels, distinct for different cryptographic purposes. Keep HKDF `info` non-empty and encode labels and payload fields unambiguously. Treat changes to existing context bytes as protocol changes.
- Use types that zeroize on drop for owned secrets, including temporary stack buffers. Create raw secret buffers inside `Zeroizing` when possible; wrap incoming or returned secret buffers immediately, before validation or early returns. Existing types that zeroize on drop need no extra wrapper.
- For custom secret-bearing structs, prefer `ZeroizeOnDrop` derives or verified field cleanup. Use a manual `Drop` implementation when necessary and add `Zeroize` only when explicit wiping is needed. Skip fields only if they are non-secret or independently zeroized on drop.
- Add `Clone` or `Serialize` to secret-bearing types only for a concrete use, explained in a nearby comment. Ensure owned copies and serialized secret buffers zeroize on drop; borrowed views rely on the secret owner's cleanup.
- Use constant-time checks for secrets, authentication tags and tokens, and comparisons that could reveal private metadata. Use library verification APIs or `subtle::ConstantTimeEq`. Ordinary equality is allowed when timing reveals only public information; default to constant-time when unsure.
- Validate lengths, formats, and bounds at network, decoding, and FFI boundaries. Enforce resource limits before input-driven allocation, computation, recursion, or accumulated state growth. Reuse existing validated limits where sufficient; otherwise add explicit caps.

## Protocol State

For Double Ratchet processing:

- Reject replays while allowing out-of-order messages whose keys are still retained.
- Authenticate the ciphertext and associated data, including the header, before committing receive-state changes. Failed processing must leave live state and cached message keys unchanged.
- Erase superseded chain keys and successfully consumed message keys.
- Bound skipped-key derivation and total retained keys; enforce cache bounds when restoring persisted state.
