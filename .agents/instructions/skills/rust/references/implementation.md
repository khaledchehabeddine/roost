# Implementation

## Control Flow

- For simple mappings that return `Result`, return `Ok` or `Err` from each `match` arm.
- Prefer method chains for simple filtering and mapping. Use `match` or loops when branching or state changes make a chain harder to read.
- When behavior depends on protocol state, match every variant explicitly.
- Use early returns for input validation.
- Name intermediate values when they clarify separate steps. Keep simple expressions inline.

### ❌ Bad

```rust
Ok(Identity::from_core(self.inner.load_identity()?)?)
```

### ✅ Good

```rust
let identity = self.inner.load_identity()?;
Ok(Identity::from_core(identity)?)
```

## State Changes

Check preconditions before changing state. Use staging or rollback when failure must leave state unchanged.

## Ownership and Allocation

Prefer borrowing or moving existing values. Clone when you need an owned copy and must keep the original.

Write serialized output directly into its destination buffer. Preallocate when the size is known.

## Resource Lifetimes

Keep guards alive throughout the operation they protect. End their scope before unrelated work.

### ❌ Bad

```rust
{
    let _lifecycle = self.lifecycle_guard();
    self.ensure_no_recovery_required()?;
}

let output = operation(&staged_store)?;
```

### ✅ Good

```rust
let _lifecycle = self.lifecycle_guard();
self.ensure_no_recovery_required()?;

let output = operation(&staged_store)?;
```

## Helpers

Extract helpers when they clarify an operation or enforce a shared rule. Short, obvious expressions can stay inline even when repeated.

## Errors

- Return failures as `Result`. Do not use `unwrap`, `expect`, or `panic!` in production code.
- Use `?` to propagate errors. Omit `From` conversions it already performs.
- Use defaults for expected absence. Propagate failures unless the operation defines a recovery path.
- Include values and limits that help diagnose a failure. Don't repeat context the error type already provides.
- Write error messages in lowercase without trailing punctuation. Preserve capitalization in names and acronyms.
