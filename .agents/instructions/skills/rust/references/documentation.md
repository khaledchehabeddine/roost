# Documentation

UniFFI copies exported items' comments into the Swift and Kotlin bindings, so app developers read them without the Rust code.

## Comments

- Make each comment stand on its own, without citing requirement IDs, ADRs, or other project documents.
- Start each documentation comment with a one-sentence summary in its own paragraph, opening with a third-person verb for a function, such as "Returns", or a noun phrase for a type.
- After the summary, add only what the signature can't show, such as a required order, changes that remain after a failure, or the reason for a surprising choice.
- Refer to other items with rustdoc links, such as ``[`ExampleError::NotFound`]``.
- Add an example only for a flow of several calls, and put it on their type, not on each method.

### ❌ Bad

```rust
impl ExampleState {
    /// Applies each update in order.
    ///
    /// Takes a list of updates and returns an error if one fails.
    fn apply_example_updates(&mut self, updates: Vec<ExampleUpdate>) -> Result<(), ExampleError> {
        for update in updates {
            self.apply(update)?;
        }
        Ok(())
    }
}
```

### ✅ Good

```rust
impl ExampleState {
    /// Applies each update in order.
    ///
    /// A failed update leaves the updates before it applied.
    fn apply_example_updates(&mut self, updates: Vec<ExampleUpdate>) -> Result<(), ExampleError> {
        for update in updates {
            self.apply(update)?;
        }
        Ok(())
    }
}
```

## Exported API

- Leave out what a Swift or Kotlin developer wouldn't know, such as Rust types, internal crate names, protocol shorthand, and wire formats.
- On each method, say what the app must persist and what it must check itself.
- Explain what Roost and the app each own on the type apps create first, since crate documentation doesn't reach the bindings.
- Write examples as one `swift` block and one `kotlin` block, never Rust.
- Write `# Errors` only on functions `roost-client` exports through UniFFI, with a bullet for each error the function can return, starting with its link.

### ❌ Bad

```rust
#[uniffi::export]
impl ExampleClient {
    /// Returns the status of a prepared operation.
    ///
    /// # Errors
    /// Returns [`ExampleError::NotFound`] if no operation has this id.
    pub fn operation_status(&self, id: u64) -> Result<ExampleStatus, ExampleError> {
        let status = self.statuses.get(&id).ok_or(ExampleError::NotFound)?;
        Ok(*status)
    }
}
```

### ✅ Good

```rust
#[uniffi::export]
impl ExampleClient {
    /// Returns the status of a prepared operation.
    ///
    /// # Errors
    /// - [`ExampleError::NotFound`] if no operation has this id.
    pub fn operation_status(&self, id: u64) -> Result<ExampleStatus, ExampleError> {
        let status = self.statuses.get(&id).ok_or(ExampleError::NotFound)?;
        Ok(*status)
    }
}
```

## Crates and Modules

- Give a module `//!` documentation only when its file name doesn't explain its purpose.
- In each `lib.rs`, follow the summary with what the crate handles, then its feature flags.
