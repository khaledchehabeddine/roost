# UniFFI Async Patterns

**Status: forward-looking.** Hermes' current FFI is fully sync. Async will become relevant when transport-ble lands or storage adapters become async.

## How it works

UniFFI 0.31 supports `async fn` exports directly. Bindings map to:
- **Swift**: `async throws` functions
- **Kotlin**: `suspend fun` with cancellation via coroutine context

No special derive — UniFFI detects `async fn`.

## Constraints

- **Tokio runtime required.** Add `tokio = { version = "1", features = ["rt"] }` when the first async export lands
- **Futures must be `Send + 'static`** — use `tokio::sync::Mutex` (not `std::sync::Mutex`) to hold across `await`
- **Cancellation**: foreign callers can drop the future mid-`await`. Multi-step operations must be safe to interrupt, or use atomic storage primitives
- **Errors** still flow through `HermesError` (see [error-boundary.md](error-boundary.md))

## When to make a function async

Genuinely awaits I/O, or supports cancellation of long-running work. Don't async to "future-proof" — runtime cost without payoff.

## See also

- UniFFI async docs: <https://mozilla.github.io/uniffi-rs/latest/futures.html>
- [error-boundary.md](error-boundary.md) — async error rules
- [type-bridges.md](type-bridges.md) — type constraints apply equally to async
