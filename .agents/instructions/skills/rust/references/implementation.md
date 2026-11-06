# Implementation

This code runs inside the app, so a failure here can crash it or leave changes behind.

## Checks

- Check every input and precondition before changing any state.
- Group repeated checks for a value in one function, such as encoding and decoding.

## State Changes

- When a failure must leave state unchanged, change a copy and replace the original only after every step succeeds.
- Keep a lock guard alive until the last step it protects.

### ❌ Bad

```rust
impl ExampleStore {
    fn prepare_example(&self) -> Result<ExamplePlan, ExampleError> {
        {
            let _guard = self.lock_example();
            self.check_example_ready()?;
        }
        self.stage_example()
    }
}
```

### ✅ Good

```rust
impl ExampleStore {
    fn prepare_example(&self) -> Result<ExamplePlan, ExampleError> {
        let _guard = self.lock_example();
        self.check_example_ready()?;
        self.stage_example()
    }
}
```

## Errors

- Return every failure as an error, and never `unwrap`, `expect`, or panic in production code, even when a call's arguments make failure impossible.
- Give an error the values that explain it, such as `TooLong { len, max }`, not `TooLong`.
- Never turn an error into a default value, such as an empty set when loading fails.

### ❌ Bad

```rust
fn load_example_set(storage: &ExampleStorage) -> Result<ExampleSet, ExampleError> {
    Ok(storage.load().ok().flatten().unwrap_or_default())
}
```

### ✅ Good

```rust
fn load_example_set(storage: &ExampleStorage) -> Result<ExampleSet, ExampleError> {
    Ok(storage.load()?.unwrap_or_default())
}
```

## Blank Lines

- Use a blank line only between steps, such as checking input and changing state, in a function body longer than ten lines.
