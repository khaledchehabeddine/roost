//! Wire-format Double Ratchet header prepended to each ciphertext.

use crate::keys::PublicKey;

/// Double Ratchet message header transmitted with each ciphertext.
pub struct Header {
    /// Ratchet public key for the sender's current sending chain.
    pub public_key: PublicKey,
    /// Number of messages sent in the sender's previous sending chain.
    pub previous_chain_length: u32,
    /// Sequence number of this message in the sender's current sending chain.
    pub message_number: u32,
}

impl Header {
    // Serializes the header as `public_key || previous_chain_length || message_number`.
    // Count fields are encoded as big-endian u32 values.
    pub(super) fn serialize(&self) -> [u8; 40] {
        let mut serialized = [0u8; 40];
        serialized[..32].copy_from_slice(self.public_key.as_bytes());
        serialized[32..36].copy_from_slice(&self.previous_chain_length.to_be_bytes());
        serialized[36..40].copy_from_slice(&self.message_number.to_be_bytes());
        serialized
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_key_pair;

    #[test]
    fn serialize_writes_public_key_and_counters() {
        let key_pair = generate_key_pair();
        let previous_chain_length = 42;
        let message_number = 7;
        let header = Header {
            public_key: key_pair.public,
            previous_chain_length,
            message_number,
        };

        let serialized = header.serialize();
        assert_eq!(&serialized[..32], key_pair.public.as_bytes());
        assert_eq!(
            u32::from_be_bytes(serialized[32..36].try_into().unwrap()),
            previous_chain_length
        );
        assert_eq!(
            u32::from_be_bytes(serialized[36..40].try_into().unwrap()),
            message_number
        );
    }
}
