# Async Test Patterns

**Status: forward-looking.** Hermes is fully sync today. The first async surface will land in `hermes-transport-ble` (BLE I/O) and possibly future async storage adapters.

## When async tests apply

- Tests that exercise `async fn` directly
- Tests verifying ordering, cancellation, or concurrent behavior
- Tests interacting with timers, channels, or future combinators

Pure logic in an async crate stays sync — only mark async what genuinely uses `await`.

## Pattern when introduced

Use `tokio` (via `tokio-test` for utilities):

- `#[tokio::test]` — single-threaded runtime by default; multi-threaded only when testing concurrency
- `#[tokio::test(start_paused = true)]` for any test involving timeouts or sleep — wall-clock dependence is flaky
- Wrap awaited ops in `tokio::time::timeout` so hung futures fail fast
- Mock async I/O at trait boundaries (define a trait, provide a test impl) — never real BLE in tests

## See also

- Tokio testing guide: <https://tokio.rs/tokio/topics/testing>
- [integration-tests.md](integration-tests.md) — async tests are typically integration tests
