# UniFFI

- Keep UniFFI declarations and host-type conversions in `roost-client`. Preserve idiomatic lower-crate APIs and add adapters only where the bindings or host contract require them.
- Receive secret buffers in owned types and wrap them in `Zeroizing` immediately in `roost-client`, before validation or early returns. Keep outgoing secrets in zeroizing types until the final binding conversion. This does not guarantee erasure of copies made by UniFFI or the host language.
- Use `#[derive(uniffi::Object)]` for shared Rust handles and `#[derive(uniffi::Record)]` for data passed by value. Objects must be `Send + Sync`; reuse existing synchronization and add thread-safe interior mutability only where needed.
- Use `#[uniffi::export(with_foreign)]` for traits the host app implements.
- Expose `ClientError` with `#[derive(uniffi::Error)]`. Its variants describe failures hosts need to distinguish; map other internal failures to `InternalError { reason: String }`.
- Keep `reason` fields diagnostic-only. Host logic uses variants and structured fields, never message text.
