use roost_protocol::IdentityKey;

const SAFETY_NUMBER_DOMAIN_TAG: &[u8] = b"RoostSafetyNumber-v1:";
const SAFETY_NUMBER_DIGITS: usize = 60;
const SAFETY_NUMBER_GROUP_SIZE: usize = 5;
const SAFETY_NUMBER_GROUPS: usize = 12;

/// A safety number derived from two permanent identity keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SafetyNumber {
    /// BLAKE3 derivation bytes before display reduction.
    pub raw_bytes: [u8; 32],
    /// 60-digit decimal value grouped as 12 blocks of five digits.
    pub grouped_decimal: String,
}

/// Errors returned by safety number derivation.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SafetyNumberError {
    /// One identity key uses a non-canonical or weak public-key encoding.
    #[error("identity key encoding is invalid")]
    InvalidIdentityKey,
}

/// Derives the display safety number for two permanent identity keys.
///
/// Both inputs must use canonical X25519 and Ed25519 public-key encodings. Discovery keys are not
/// inputs, so discovery key rotation does not change the safety number for the same two identity
/// keys. The two canonical identity key encodings are sorted before hashing so both parties derive
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
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use roost_crypto::{generate_key_pair, generate_signing_key_pair};

    #[test]
    fn decimal_reduction_left_pads_to_sixty_digits() {
        let mut raw_bytes = [0u8; 32];
        raw_bytes[31] = 7;
        assert_eq!(
            grouped_decimal(&raw_bytes),
            "00000 00000 00000 00000 00000 00000 00000 00000 00000 00000 00000 00007"
        );
    }

    struct Setup {
        local_identity: IdentityKey,
        contact_identity: IdentityKey,
    }

    fn setup() -> Setup {
        let mut rng = ChaCha20Rng::from_seed([0x19; 32]);
        let local_signing = generate_signing_key_pair(&mut rng);
        let local_key_pair = generate_key_pair(&mut rng);
        let contact_signing = generate_signing_key_pair(&mut rng);
        let contact_key_pair = generate_key_pair(&mut rng);

        Setup {
            local_identity: IdentityKey {
                x25519_public_key: *local_key_pair.public.as_bytes(),
                ed25519_verifying_key: local_signing.verifying.to_bytes(),
            },
            contact_identity: IdentityKey {
                x25519_public_key: *contact_key_pair.public.as_bytes(),
                ed25519_verifying_key: contact_signing.verifying.to_bytes(),
            },
        }
    }

    /// Pinned on purpose, unlike Roost's other derivations. People compare safety numbers across
    /// app versions, so a change to the derivation or the display must fail here before it ships.
    #[test]
    fn safety_number_matches_expected_hash_and_display() {
        let bytes = |hex: &str| -> [u8; 32] { hex::decode(hex).unwrap().try_into().unwrap() };
        let first = IdentityKey {
            x25519_public_key: bytes(
                "cea8522b478dd6836e54235f6e425a69fd8a07e0113a6393390235298aa76207",
            ),
            ed25519_verifying_key: bytes(
                "734cce51a84fbd45336303ce2a3cb6d7cdcb6703d5eb80f1eacf42613487a8f0",
            ),
        };
        let second = IdentityKey {
            x25519_public_key: bytes(
                "3d4dafeef11bf354d5038ed7987cfcaa441845be52f1b8d14c4b4a4e2389f56b",
            ),
            ed25519_verifying_key: bytes(
                "b12661824d74f494a38a1dda9d0594e1f4cdd049af4f283d42145c82d9819142",
            ),
        };
        let number = derive_safety_number(first, second).unwrap();
        assert_eq!(
            number.raw_bytes,
            bytes("11ec6a72d8289a704f13391812abedf2d580658ddb0a045f6e255ab29b584c0e")
        );
        assert_eq!(
            number.grouped_decimal,
            "37847 72638 08075 94309 68303 47906 65306 81346 83769 30836 34772 40846"
        );
        assert_eq!(
            derive_safety_number(second, first).unwrap().raw_bytes,
            number.raw_bytes
        );
    }

    #[test]
    fn safety_number_changes_with_each_identity_key_half() {
        let setup = setup();
        let mut rng = ChaCha20Rng::from_seed([0x5A; 32]);
        let other_x25519 = *generate_key_pair(&mut rng).public.as_bytes();
        let other_ed25519 = generate_signing_key_pair(&mut rng).verifying.to_bytes();
        let local = setup.local_identity;
        let contact = setup.contact_identity;
        let expected = derive_safety_number(local, contact).unwrap();

        for (first, second) in [
            (
                IdentityKey {
                    x25519_public_key: other_x25519,
                    ..local
                },
                contact,
            ),
            (
                IdentityKey {
                    ed25519_verifying_key: other_ed25519,
                    ..local
                },
                contact,
            ),
            (
                local,
                IdentityKey {
                    x25519_public_key: other_x25519,
                    ..contact
                },
            ),
            (
                local,
                IdentityKey {
                    ed25519_verifying_key: other_ed25519,
                    ..contact
                },
            ),
        ] {
            assert_ne!(derive_safety_number(first, second).unwrap(), expected);
        }
    }

    #[test]
    fn safety_number_derivation_rejects_non_canonical_identity_key() {
        let setup = setup();
        let mut invalid = setup.contact_identity;
        invalid.x25519_public_key = [0xff; 32];
        assert_eq!(
            derive_safety_number(setup.local_identity, invalid),
            Err(SafetyNumberError::InvalidIdentityKey)
        );
    }
}
