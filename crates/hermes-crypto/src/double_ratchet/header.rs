use crate::keys::PublicKey;

/// Message header transmitted alongside each ciphertext.
pub struct Header {
    pub public_key: PublicKey,
    pub pn: u32,
    pub n: u32,
}

impl Header {
    /// Serializes the header into a fixed 40-byte representation.
    ///
    /// Layout: 32-byte ratchet public key || 4-byte pn (big-endian) || 4-byte n (big-endian).
    pub(super) fn serialize(&self) -> [u8; 40] {
        let mut buf = [0u8; 40];
        buf[..32].copy_from_slice(self.public_key.as_bytes());
        buf[32..36].copy_from_slice(&self.pn.to_be_bytes());
        buf[36..40].copy_from_slice(&self.n.to_be_bytes());
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_key_pair;

    #[test]
    fn header_serialize_round_trip() {
        let kp = generate_key_pair();
        let header = Header {
            public_key: kp.public,
            pn: 42,
            n: 7,
        };

        let buf = header.serialize();
        assert_eq!(&buf[..32], kp.public.as_bytes());
        assert_eq!(u32::from_be_bytes(buf[32..36].try_into().unwrap()), 42);
        assert_eq!(u32::from_be_bytes(buf[36..40].try_into().unwrap()), 7);
    }
}
