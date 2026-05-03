//! BLE transport for Hermes — placeholder.
//!
//! This crate is a stub. The real implementation will provide a peer-to-peer transport over
//! Bluetooth Low Energy, suitable for ferrying Hermes ratchet messages between nearby devices
//! without an internet relay. Design is pending — track the work in the project's transport
//! issues.

/// Placeholder until the BLE transport is implemented. Returns `left + right`.
pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
