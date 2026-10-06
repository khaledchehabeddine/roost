# UniFFI

The app calls Roost only through generated Swift and Kotlin code, so `roost-client`'s exports are the API.

## Boundary

- Keep every UniFFI attribute and host-type conversion in `roost-client`.
- Write a UniFFI record's conversions as crate-private methods, such as `from_core` and `to_core`, not `From` impls, which can't be made private.
- Regenerate the bindings after editing an export's doc comment, since UniFFI counts doc comments in its API checksums and stale bindings fail to load.

## Types

- Expose every UniFFI time value as integer milliseconds, such as `created_at_millis`.
- Take a secret argument as `Vec<u8>` or `String`, not `&[u8]` or `&str`, since a borrowed one leaves a copy in freed memory.
- Export a trait the host implements with `#[uniffi::export(with_foreign)]`.

## Errors

- Share one error type across exported functions, and add a variant only for a failure hosts handle differently.
- Build each `reason` from the error's whole `source()` chain, such as `example storage failed: disk full`, not `example storage failed`.
