# API

Every caller ships in the same app as this code, so only stored data outlives a release.

## Types

- Add a trait or generic parameter only when production code needs more than one implementation or input type, or for the random number generator.
- Don't mark enums `#[non_exhaustive]`.
- Use `SystemTime` for points in time and `Duration` for spans, and an integer only where a time is signed, stored, or encoded.
- Check a value once at the boundary, then pass it inward in a type that can only hold valid values.

### ❌ Bad

```rust
fn derive_example_key(secret: &[u8]) -> Result<ExampleKey, ExampleError> {
    let secret: &[u8; 32] = secret.try_into()?;
    Ok(ExampleKey::derive(secret))
}
```

### ✅ Good

```rust
fn derive_example_key(secret: &[u8; 32]) -> ExampleKey {
    ExampleKey::derive(secret)
}
```

## Visibility

- Keep modules private and re-export the public API from `lib.rs` by name, not with `*`.
- Give each item the narrowest visibility its callers need: private, `pub(super)`, `pub(crate)`, or `pub`.
- Re-exports don't count as callers, and a test counts only when the item is its only way to read or set stored state.
- Re-export what callers need from lower workspace crates.
- Import another workspace crate's items into tests through `[dev-dependencies]`, never by making or re-exporting them publicly.
- Keep a type that holds a secret private unless callers must pass or receive that secret.

## Errors

- Give each module or operation an error enum that lists only the failures it can return.
- Derive `Display`, `Error`, and `From` with `thiserror`.
- Wrap a lower-level error with `#[from]` or `#[source]`, and keep its message out of the outer message.

### ❌ Bad

```rust
#[derive(Debug, thiserror::Error)]
enum ExampleError {
    #[error("example signature failed: {0}")]
    Signature(#[from] SignatureError),
}
```

### ✅ Good

```rust
#[derive(Debug, thiserror::Error)]
enum ExampleError {
    #[error("example signature failed")]
    Signature(#[from] SignatureError),
}
```

## Stored Data

- Start each encoding with its version, and reject an unknown version with its own error before decoding the rest.
- Leave the version off an encoding that only ever sits inside another one.
- Bump the version when a change alters how an existing value encodes or gives old bytes a new meaning.
- Don't write migration code for older versions until a release promises that stored data survives upgrades.
- Encode each type through one private `*Wire` struct, not the domain type, and derive both `Serialize` and `Deserialize` on it. Pair a borrowing encode struct with an owning decode struct when one struct would copy a secret or a large buffer to encode.
