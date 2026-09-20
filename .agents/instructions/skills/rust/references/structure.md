# Structure

## Modules

Group types and helpers into modules by responsibility. Split a module when a distinct responsibility is easier to understand on its own.

## Declarations

- Put module declarations, imports, re-exports, and shared constants first.
- Keep each type beside its inherent and trait implementations.
- Keep an operation's input types, functions, and errors together.
- Use explicit `pub use` re-exports.

### ❌ Bad

```text
struct MessageTranscriptInput { ... }
enum MessageEncodingError { ... }
enum SealedPayloadError { ... }

impl fmt::Display for MessageEncodingError { ... }
impl Error for MessageEncodingError {}
impl fmt::Display for SealedPayloadError { ... }
impl Error for SealedPayloadError {}

fn message_transcript(...) { ... }
fn pad_sealed_payload(...) { ... }
fn unpad_sealed_payload(...) { ... }
```

### ✅ Good

```text
struct MessageTranscriptInput { ... }
fn message_transcript(...) { ... }

enum MessageEncodingError { ... }
impl fmt::Display for MessageEncodingError { ... }
impl Error for MessageEncodingError {}

fn pad_sealed_payload(...) { ... }
fn unpad_sealed_payload(...) { ... }

enum SealedPayloadError { ... }
impl fmt::Display for SealedPayloadError { ... }
impl Error for SealedPayloadError {}
```
