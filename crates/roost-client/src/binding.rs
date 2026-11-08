//! Standalone IK/DK binding verification exposed through UniFFI.
//!
//! Roost checks both directions of the mutual binding on every path that starts a session or takes
//! an inbox grant. Apart from decoding a contact publication, neither is reachable from a binding
//! without this module. A request checks them only once the app holds a whole prekey bundle. A
//! client that looks someone up from a typed discovery key must decide whether the identity a relay
//! answered with is the one that discovery key vouches for *before* it asks them.
//!
//! The functions here take public material only and return nothing but a verdict, so they are not
//! a signing oracle. They are not a general Ed25519 verification oracle either: each one fixes its
//! own context and rebuilds the payload from the identity key it was handed, so a caller chooses
//! neither the context nor the shape of the signed bytes.

use crate::encoding::{fixed_32, fixed_64};
use crate::error::RoostError;
use crate::identity::{Identity, IdentityKey};
use roost_core::{
    PublicIdentityKey as CorePublicIdentityKey, Signature,
    verify_discovery_to_identity_binding as crypto_verify_discovery_to_identity_binding,
    verify_public_identity_key,
};
use roost_protocol::parse_ed25519_verifying_key_bytes;

/// Verifies that an identity's binding signature ties its agreement key to its signing key.
///
/// It shows only that whoever holds the signing key claimed the agreement key beside it, not which
/// discovery key, if any, vouches for the identity. When the identity came from a discovery key
/// lookup, also check it with [`verify_discovery_to_identity_binding`] against the discovery key
/// the user supplied. A relay's signature checked under a key the same relay handed over proves
/// only that the relay is self-consistent.
///
/// # Errors
/// - [`RoostError::AuthenticationFailed`] if the signature doesn't verify, so the identity doesn't
///   bind.
/// - [`RoostError::InvalidData`] if a key isn't 32 bytes, the signature isn't 64, or the signing
///   key isn't a valid point.
#[uniffi::export]
pub fn verify_identity_key_binding(identity: Identity) -> Result<(), RoostError> {
    Ok(verify_public_identity_key(&identity.to_core()?)?)
}

/// Verifies that `discovery_verifying_key` signed `identity`'s two public keys.
///
/// This check is the whole security of adding a contact by discovery key: the relay answers a
/// lookup with an identity, and nothing else shows that the discovery key authorized it. Pass the
/// discovery key the user typed, never one read from the response being checked. The signature
/// doesn't cover the identity's own binding signature, so check that with
/// [`verify_identity_key_binding`] too.
///
/// # Errors
/// - [`RoostError::AuthenticationFailed`] if the signature doesn't verify, including a valid
///   signature made for the identity's own binding.
/// - [`RoostError::InvalidData`] if a key isn't 32 bytes, the signature isn't 64, or either
///   signing key isn't a canonically encoded, non-weak point.
#[uniffi::export]
pub fn verify_discovery_to_identity_binding(
    identity: IdentityKey,
    discovery_verifying_key: Vec<u8>,
    signature: Vec<u8>,
) -> Result<(), RoostError> {
    let identity = binding_payload_identity_key(&identity)?;
    let discovery_verifying_key = parse_ed25519_verifying_key_bytes(&fixed_32(
        &discovery_verifying_key,
        "discovery ed25519 verifying key",
    )?)
    .ok_or_else(|| RoostError::InvalidData {
        reason: "discovery ed25519 verifying key is not a canonical, non-weak point".into(),
    })?;
    let signature =
        Signature::from_bytes(&fixed_64(&signature, "discovery to identity signature")?);
    Ok(crypto_verify_discovery_to_identity_binding(
        &identity,
        &discovery_verifying_key,
        &signature,
    )?)
}

/// Builds the public identity key the discovery key's verifier takes from an identity key that
/// carries no signature.
///
/// [`crypto_verify_discovery_to_identity_binding`] reads exactly two fields of the key, the
/// X25519 and Ed25519 halves, because those two are the entire signed payload. The signature slot
/// is filled with zeros and is never read — it belongs to the *other* direction, and a caller who
/// wants that direction checked calls [`verify_identity_key_binding`], which reads a real one. The
/// zeros are here so this function cannot be mistaken for having checked something it did not.
fn binding_payload_identity_key(
    identity: &IdentityKey,
) -> Result<CorePublicIdentityKey, RoostError> {
    const UNREAD_BINDING_SIGNATURE: [u8; 64] = [0u8; 64];

    let key = identity.to_core()?;
    Ok(CorePublicIdentityKey::from_bytes(
        &key.x25519_public_key,
        &key.ed25519_verifying_key,
        &UNREAD_BINDING_SIGNATURE,
    )?)
}

#[cfg(test)]
mod tests {
    use super::{verify_discovery_to_identity_binding, verify_identity_key_binding};
    use crate::{Identity, IdentityKey, RoostError};
    use roost_crypto::{
        DiscoveryKey, PublicIdentityKey, Signature, SigningKeyPair, sign_identity_key_binding,
    };

    const IDENTITY_X25519: [u8; 32] = [0x22; 32];
    const IDENTITY_SIGNING_SECRET: [u8; 32] = [0x11; 32];
    const DISCOVERY_SIGNING_SECRET: [u8; 32] = [0x33; 32];

    fn fixed_identity() -> IdentityKey {
        IdentityKey {
            agreement_key: IDENTITY_X25519.to_vec(),
            signing_key: SigningKeyPair::from_signing_bytes(&IDENTITY_SIGNING_SECRET)
                .verifying
                .to_bytes()
                .to_vec(),
        }
    }

    // Signs `fixed_identity()` with the discovery signing key, as a peer's discovery key does.
    // The DK→IK signature covers only the identity's two public halves, so the discovery key's
    // other fields and the identity's own binding signature take placeholder values.
    fn discovery_to_identity_signature() -> Vec<u8> {
        let identity = PublicIdentityKey {
            public_key: IDENTITY_X25519.into(),
            verifying_key: SigningKeyPair::from_signing_bytes(&IDENTITY_SIGNING_SECRET).verifying,
            binding_signature: Signature::from_bytes(&[0; 64]),
        };
        DiscoveryKey::from_secret_bytes(&[0; 32], &DISCOVERY_SIGNING_SECRET, 0, 0, [0; 64])
            .sign_identity_binding(&identity)
            .unwrap()
            .to_bytes()
            .to_vec()
    }

    fn discovery_verifying_key() -> Vec<u8> {
        SigningKeyPair::from_signing_bytes(&DISCOVERY_SIGNING_SECRET)
            .verifying
            .to_bytes()
            .to_vec()
    }

    #[test]
    fn discovery_to_identity_binding_verifies_through_the_export() {
        verify_discovery_to_identity_binding(
            fixed_identity(),
            discovery_verifying_key(),
            discovery_to_identity_signature(),
        )
        .expect("a discovery key's binding for the identity it signed must verify");
    }

    #[test]
    fn discovery_to_identity_binding_fails_with_one_byte_altered() {
        let mut tampered = discovery_to_identity_signature();
        tampered[0] ^= 0x01;

        match verify_discovery_to_identity_binding(
            fixed_identity(),
            discovery_verifying_key(),
            tampered,
        ) {
            Err(RoostError::AuthenticationFailed { .. }) => {}
            other => {
                panic!("expected AuthenticationFailed for a tampered signature, got {other:?}")
            }
        }
    }

    /// `RoostIKBinding-v1:` and `RoostDKToIK-v1:` sign a byte-identical 64-byte payload, so only
    /// the context separates them. Exporting the two directions as one function that took a
    /// caller-chosen context would have handed that separation to the caller; exporting them as two
    /// functions that each fix their own is what keeps it here.
    #[test]
    fn the_two_identity_contexts_do_not_accept_each_others_signatures() {
        let identity_signing = SigningKeyPair::from_signing_bytes(&IDENTITY_SIGNING_SECRET);
        let discovery_signing = SigningKeyPair::from_signing_bytes(&DISCOVERY_SIGNING_SECRET);
        let self_binding =
            sign_identity_key_binding(&identity_signing, &IDENTITY_X25519.into()).unwrap();

        // The real self-binding must not pass as a discovery-to-identity binding, even when it is
        // checked under the key that actually made it.
        match verify_discovery_to_identity_binding(
            fixed_identity(),
            identity_signing.verifying.to_bytes().to_vec(),
            self_binding.to_bytes().to_vec(),
        ) {
            Err(RoostError::AuthenticationFailed { .. }) => {}
            other => panic!("expected AuthenticationFailed across contexts, got {other:?}"),
        }

        // And the DK→IK signature must not pass as a self-binding, checked under the discovery key
        // that made it, so that only the context can be what rejects it.
        match verify_identity_key_binding(Identity {
            key: IdentityKey {
                agreement_key: IDENTITY_X25519.to_vec(),
                signing_key: discovery_signing.verifying.to_bytes().to_vec(),
            },
            binding_signature: discovery_to_identity_signature(),
        }) {
            Err(RoostError::AuthenticationFailed { .. }) => {}
            other => panic!("expected AuthenticationFailed across contexts, got {other:?}"),
        }
    }

    /// The substitution the DK→IK check exists to catch: a relay answers a discovery-key lookup
    /// with an identity of its own, correctly self-bound, that the typed discovery key never
    /// signed.
    #[test]
    fn a_substituted_identity_fails_against_the_typed_discovery_key() {
        let impostor = SigningKeyPair::from_signing_bytes(&[0x44; 32]);
        let impostor_identity = IdentityKey {
            agreement_key: IDENTITY_X25519.to_vec(),
            signing_key: impostor.verifying.to_bytes().to_vec(),
        };
        let self_binding = sign_identity_key_binding(&impostor, &IDENTITY_X25519.into()).unwrap();

        // The impostor's own self-binding holds — substitution does not fail here.
        verify_identity_key_binding(Identity {
            key: impostor_identity.clone(),
            binding_signature: self_binding.to_bytes().to_vec(),
        })
        .expect("a self-consistent impostor identity self-binds");

        // It fails here, which is the only place it can.
        match verify_discovery_to_identity_binding(
            impostor_identity,
            discovery_verifying_key(),
            discovery_to_identity_signature(),
        ) {
            Err(RoostError::AuthenticationFailed { .. }) => {}
            other => {
                panic!("expected AuthenticationFailed for a substituted identity, got {other:?}")
            }
        }
    }

    #[test]
    fn malformed_input_is_invalid_data_not_a_failed_binding() {
        let identity = fixed_identity();

        for (label, result) in [
            (
                "short discovery key",
                verify_discovery_to_identity_binding(
                    fixed_identity(),
                    vec![0u8; 31],
                    discovery_to_identity_signature(),
                ),
            ),
            (
                "short signature",
                verify_discovery_to_identity_binding(
                    fixed_identity(),
                    discovery_verifying_key(),
                    vec![0u8; 63],
                ),
            ),
            (
                "non-canonically encoded discovery key",
                verify_discovery_to_identity_binding(
                    fixed_identity(),
                    vec![0xFF; 32],
                    discovery_to_identity_signature(),
                ),
            ),
            // A small-order key is the one that is not merely malformed: signatures under it
            // verify for keys nobody controls, so an export that accepted one would report a
            // binding that binds nothing. Every other Roost entry point refuses it, and this one
            // has to as well — it is the entry point that takes a key straight from a relay.
            (
                "weak discovery key",
                verify_discovery_to_identity_binding(
                    fixed_identity(),
                    vec![0u8; 32],
                    discovery_to_identity_signature(),
                ),
            ),
            (
                "short identity agreement key",
                verify_discovery_to_identity_binding(
                    IdentityKey {
                        agreement_key: vec![0u8; 16],
                        signing_key: identity.signing_key.clone(),
                    },
                    discovery_verifying_key(),
                    discovery_to_identity_signature(),
                ),
            ),
            (
                "off-curve identity verifying key",
                verify_identity_key_binding(Identity {
                    key: IdentityKey {
                        agreement_key: identity.agreement_key.clone(),
                        signing_key: vec![0xFF; 32],
                    },
                    binding_signature: vec![0u8; 64],
                }),
            ),
        ] {
            match result {
                Err(RoostError::InvalidData { .. }) => {}
                other => panic!("expected InvalidData for {label}, got {other:?}"),
            }
        }
    }
}
