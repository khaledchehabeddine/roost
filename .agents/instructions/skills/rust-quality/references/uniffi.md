# UniFFI

- Wrap FFI-incompatible core types in `aether-uniffi`: borrowed strings or bytes, lifetimes, tuples, unsupported external types, and trait objects without `#[uniffi::export(with_foreign)]`.
- Pass secret bytes as bare `Vec<u8>` and wrap them in `Zeroizing` immediately in the Rust adapter, not in client code.
- Wrap stateful types with `#[derive(uniffi::Object)]` and interior mutability so internal layout can evolve independently of the generated API.
- Mark client-implemented traits with `#[uniffi::export(with_foreign)]`.
- Export only `#[derive(uniffi::Error)]` errors. Convert crate errors to `AetherError`; library errors and panics must not cross the boundary.
- Use client-actionable variants such as `AlreadyExists` and `NotFound`. Reduce failures clients cannot handle to `InternalError { reason: String }`; keep `reason` log-safe.
- Treat `crates/aether-uniffi/src` declarations as the binding source. Generated Swift and Kotlin files stay under `target/` and are not checked in.
- Run `scripts/check.sh bindings` for binding-surface changes. Before publish, `scripts/check.sh full --base <base>` routes generated binding and consumer checks from changed paths.
