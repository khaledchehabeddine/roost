//! Exercises the public Transport Binding constructor across the Core boundary.

use roost_core::{TransportBinding, TransportBindingError};

#[test]
fn transport_binding_preserves_exact_caller_bytes() {
    let bytes = vec![0x41, 0x00, 0xff, 0x7f];
    let binding = TransportBinding::new(bytes.clone()).expect("binding should be valid");

    assert_eq!(binding.as_bytes(), bytes);
}

#[test]
fn transport_binding_rejects_empty_bytes() {
    assert_eq!(
        TransportBinding::new(Vec::new()),
        Err(TransportBindingError::Empty)
    );
}

#[test]
fn transport_binding_enforces_the_external_associated_data_limit() {
    assert!(TransportBinding::new(vec![0x41; TransportBinding::MAX_LEN]).is_ok());
    assert_eq!(
        TransportBinding::new(vec![0x41; TransportBinding::MAX_LEN + 1]),
        Err(TransportBindingError::TooLong {
            length: TransportBinding::MAX_LEN + 1,
            maximum: TransportBinding::MAX_LEN,
        })
    );
}
