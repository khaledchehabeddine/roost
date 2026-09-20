# Naming

Use [CONTEXT_MAP.md](../../../../../CONTEXT_MAP.md) to find the owning crate's vocabulary when domain terms matter.

## Names

- Keep local names short when their role is clear, without protocol shorthand. Distinguish similar values by role, including in tests.
- Start action functions with a verb: `generate_*`, `rotate_*`, `verify_*`.
- Name accessors after the value they expose, without `get_`: `current_bundle`, `public_key`.
- Use `new` for the primary constructor, `from_*` for alternate input forms, and `with_*` for explicit configuration.
- Don't add `try_` solely because a function returns `Result`. Use it to distinguish alternative behavior or follow a trait's required name.
- Use `*Error` for errors and `*Bundle` for containers of related public material. Avoid `*Helper`, `*Util`, and `*Service`.
- Use `*Manager` for a crate-private type that owns the stored lifecycle of one kind of key material: `IdentityManager` for `Identity`.

## Predicates

Phrase predicates as yes/no questions: `is_*` or `has_*` for states and properties, and a present-tense verb for relations (`contains_*`, `requires_*`, `matches`). Don't give an action verb to a function that returns `bool`.

### ❌ Bad

```rust
pub fn validate_x25519_public_key(bytes: &[u8; PUBLIC_KEY_LEN]) -> bool
```

### ✅ Good

```rust
pub fn is_valid_x25519_public_key(bytes: &[u8; PUBLIC_KEY_LEN]) -> bool
```

## Conversions

- `as_*` borrows cheaply, `to_*` builds a new value from a borrow or a `Copy` value, and `into_*` consumes `self`.
- Convert between `roost-client` records and lower-crate types with crate-private inherent methods named for the crate: `from_core`, `to_core`, `into_core`, `from_protocol`, `to_protocol`. Return `Result` only when the conversion can fail.
- Implement `From` only for error conversions that `?` needs. Trait impls are always public, so other `From` or `TryFrom` impls would add adapter internals to the entry crate's API.

### ❌ Bad

```rust
impl From<roost_core::ContactTrustState> for ContactTrustState { … }

trust_state: value.trust_state.into(),
```

### ✅ Good

```rust
impl ContactTrustState {
    fn from_core(value: roost_core::ContactTrustState) -> Self { … }
}

trust_state: ContactTrustState::from_core(value.trust_state),
```

## Time

- Name an instant after its event with `_at`: `created_at`, `sent_at`, `last_retried_at`. Use `now` or `reference_time` for times that are not events.
- Use `SystemTime` for current and reference times and `Duration` for windows: `now`, `reference_time`, `grace_window`.
- Add the unit to recorded time wherever it is signed, authenticated, persisted, or encoded: `created_at_secs`, `sent_at_millis`.
- Expose every UniFFI time value in milliseconds: `created_at_millis`, `reference_time_millis`, `grace_window_millis`.

### ❌ Bad

```rust
// UniFFI record
pub struct SignedPreKeyBundle {
    pub created_at: u64,
}

fn certificate_is_expired(expires_at_secs: u64, reference_secs: u64, grace_secs: u64) -> bool
```

### ✅ Good

```rust
// UniFFI record
pub struct SignedPreKeyBundle {
    pub created_at_millis: u64,
}

fn certificate_is_expired(
    expires_at_secs: u64,
    reference_time: SystemTime,
    grace_window: Duration,
) -> bool
```

## Abbreviations

- Spell out protocol shorthand in every name, including locals, so readers need no protocol or specification background: `IDENTITY_KEY_LEN`, not `IK_LEN`; `next_chain_key`, not `ck`.
- Keep standard terms abbreviated everywhere: `X3DH`, `AEAD`, `KDF`, `HKDF`, `MAC`, `DH`, `KAT`, `FFI`, `len`, `id`. Use `id`, not `identifier`, in names.
- Spell out names in code that implements a specification, and cite the specification's name in a comment: `derive_chain_and_message_keys` implements `KDF_CK`; `sending_chain_key` is `CKs`.
- Case an acronym as one word: `FullX3dhSetup`, `X3DH_ADDITIVE_SHARED_SECRET_HEADROOM`, `full_x3dh_setup`, `KeyStoreOperationId`.

### ❌ Bad

```rust
struct RatchetState {
    dhs: KeyPair,
    cks: Option<ChainKey>,
    pn: u32,
}
```

### ✅ Good

```rust
struct RatchetState {
    // Sending ratchet key pair (`DHs`).
    sending_ratchet_key_pair: KeyPair,
    // Sending chain key (`CKs`).
    sending_chain_key: Option<ChainKey>,
    // Number of messages sent in the previous sending chain (`PN`).
    previous_chain_length: u32,
}
```
