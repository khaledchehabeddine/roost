use roost_protocol::IdentityKey;

const SAFETY_NUMBER_DOMAIN_TAG: &[u8] = b"RoostSafetyNumber-v1:";
const SAFETY_NUMBER_DIGITS: usize = 60;
const SAFETY_NUMBER_GROUP_SIZE: usize = 5;
const SAFETY_NUMBER_GROUPS: usize = 12;

/// A Safety Number derived from two permanent Identity Keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SafetyNumber {
    /// BLAKE3 derivation bytes before display reduction.
    pub raw_bytes: [u8; 32],
    /// 60-digit decimal value grouped as 12 blocks of five digits.
    pub grouped_decimal: String,
}

/// Errors returned by Safety Number derivation.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SafetyNumberError {
    /// One Identity Key uses a non-canonical or weak public-key encoding.
    #[error("identity key encoding is invalid")]
    InvalidIdentityKey,
}

/// Derives the display Safety Number for two permanent Identity Keys.
///
/// Both inputs must use canonical X25519 and Ed25519 public-key encodings. Discovery Keys are not
/// inputs, so Discovery Key rotation does not change the Safety Number for the same two Identity
/// Keys. The two canonical Identity Key encodings are sorted before hashing so both parties derive
/// the same value.
pub fn derive_safety_number(
    first: IdentityKey,
    second: IdentityKey,
) -> Result<SafetyNumber, SafetyNumberError> {
    validate_identity_key(&first)?;
    validate_identity_key(&second)?;

    let mut encodings = [first.canonical_encoding(), second.canonical_encoding()];
    encodings.sort();

    let mut hasher = blake3::Hasher::new();
    hasher.update(SAFETY_NUMBER_DOMAIN_TAG);
    hasher.update(&encodings[0]);
    hasher.update(&encodings[1]);
    let raw_bytes = *hasher.finalize().as_bytes();

    Ok(SafetyNumber {
        raw_bytes,
        grouped_decimal: grouped_decimal(&raw_bytes),
    })
}

fn validate_identity_key(identity_key: &IdentityKey) -> Result<(), SafetyNumberError> {
    identity_key
        .is_valid()
        .then_some(())
        .ok_or(SafetyNumberError::InvalidIdentityKey)
}

fn grouped_decimal(raw_bytes: &[u8; 32]) -> String {
    let mut digits = [0u8; SAFETY_NUMBER_DIGITS];
    for byte in raw_bytes {
        let mut carry = u16::from(*byte);
        for digit in &mut digits {
            let value = u16::from(*digit) * 256 + carry;
            *digit = (value % 10) as u8;
            carry = value / 10;
        }
    }

    let mut display = String::with_capacity(SAFETY_NUMBER_DIGITS + SAFETY_NUMBER_GROUPS - 1);
    for group in (0..SAFETY_NUMBER_GROUPS).rev() {
        if group != SAFETY_NUMBER_GROUPS - 1 {
            display.push(' ');
        }
        let start = group * SAFETY_NUMBER_GROUP_SIZE;
        let end = start + SAFETY_NUMBER_GROUP_SIZE;
        for digit in digits[start..end].iter().rev() {
            display.push(char::from(b'0' + *digit));
        }
    }
    display
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_reduction_left_pads_to_sixty_digits() {
        let mut raw_bytes = [0u8; 32];
        raw_bytes[31] = 7;

        assert_eq!(
            grouped_decimal(&raw_bytes),
            "00000 00000 00000 00000 00000 00000 00000 00000 00000 00000 00000 00007"
        );
    }
}
