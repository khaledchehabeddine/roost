#![cfg_attr(
    not(test),
    forbid(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented
    )
)]

//! Generates UniFFI scaffolding bindings.

fn main() {
    uniffi::uniffi_bindgen_main()
}
