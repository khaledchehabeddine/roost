# Cryptography

The app holds private keys and messages and reads bytes from anyone, so a mistake here can leak them.

## Primitives

- Use an established crate for every cryptographic primitive and construction, even one that looks simple, such as HMAC instead of hashing a key with a message.
- Take the random number generator as a parameter, and pass `OsRng` in production and a seeded generator in tests.
- Never encrypt more than one message with the same key and nonce.
- Compare secrets, tags, tokens, and keys in constant time, with `ct_eq` or the crate's verify method.

## Labels

- Give each key derivation, signature, and hash its own label starting with `Roost`, such as `b"RoostExample-v1:"`, unless the input comes from a published specification.
- When a label changes, bump the version of each encoding whose keys, signatures, or hashes depend on it.
- In bytes that are signed, hashed, or used to derive a key, put a big-endian `u32` length before each variable-length field.

### ❌ Bad

```rust
fn example_signed_bytes(name: &[u8], note: &[u8]) -> Vec<u8> {
    [EXAMPLE_LABEL, name, note].concat()
}
```

### ✅ Good

```rust
fn example_signed_bytes(name: &[u8], note: &[u8]) -> Result<Vec<u8>, TryFromIntError> {
    let mut bytes = EXAMPLE_LABEL.to_vec();
    for field in [name, note] {
        bytes.extend_from_slice(&u32::try_from(field.len())?.to_be_bytes());
        bytes.extend_from_slice(field);
    }
    Ok(bytes)
}
```

## Secrets

- Don't implement `Debug` on a type that holds a secret, and keep secrets out of error messages and logs.
- Implement `Clone` on a type that holds a secret only when code needs a copy, and never on a public type.
- Don't let a `Vec` of secret bytes grow, since it can leave copies in freed memory.
- Hold every owned secret in a type that zeroizes on drop from the moment it's created or received, including temporary buffers, wire structs, and encoded bytes.

### ❌ Bad

```rust
fn example_secret(bytes: Vec<u8>) -> Result<Zeroizing<[u8; 32]>, ExampleError> {
    let secret: [u8; 32] = bytes.try_into().map_err(|_| ExampleError::Length)?;
    Ok(Zeroizing::new(secret))
}
```

### ✅ Good

```rust
fn example_secret(bytes: Vec<u8>) -> Result<Zeroizing<[u8; 32]>, ExampleError> {
    let bytes = Zeroizing::new(bytes);
    let secret: &[u8; 32] = bytes[..].try_into().map_err(|_| ExampleError::Length)?;
    Ok(Zeroizing::new(*secret))
}
```

## Untrusted Input

- Before allocating or looping on a size, count, or depth that untrusted input or stored state sets, check it against a named limit, unless an earlier check already bounds it.
- Reject input that has bytes left over after decoding.

### ❌ Bad

```rust
fn decode_example_message(bytes: &[u8]) -> Result<ExampleWire, ExampleError> {
    postcard::from_bytes(bytes).map_err(|_| ExampleError::Decode)
}
```

### ✅ Good

```rust
fn decode_example_message(bytes: &[u8]) -> Result<ExampleWire, ExampleError> {
    let (wire, rest) = postcard::take_from_bytes(bytes).map_err(|_| ExampleError::Decode)?;
    if !rest.is_empty() {
        return Err(ExampleError::Decode);
    }
    Ok(wire)
}
```

## Protocol State

- Change protocol state, such as a ratchet or a one-time prekey, only after the whole message, header included, authenticates, and leave it unchanged when it doesn't.
- Delete a message key once it decrypts its message, and a chain key once it's replaced.
