//! Standalone checks of the signatures that bind an identity key and a discovery key.
//!
//! Each check fixes its own signature context and rebuilds the signed bytes from the keys it's
//! given, so the app can't make one check accept another kind of signature.

use crate::encoding::{fixed_32, fixed_64};
use crate::error::RoostError;
use crate::identity::{Identity, IdentityKey};
use roost_core::{
    PublicKey, Signature,
    verify_discovery_to_identity_binding as crypto_verify_discovery_to_identity_binding,
    verify_public_identity_key,
};
use roost_protocol::{is_valid_x25519_public_key, parse_ed25519_verifying_key_bytes};

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
/// Adding a contact by discovery key relies on this check alone. The relay answers a lookup with an
/// identity, and nothing else shows that the discovery key authorized it. Pass the discovery key
/// the user typed, never one read from the response being checked. The signature doesn't cover the
/// identity's own binding signature, so check that with [`verify_identity_key_binding`] too.
///
/// # Errors
/// - [`RoostError::AuthenticationFailed`] if the signature doesn't verify, including a valid
///   signature made for the identity's own binding.
/// - [`RoostError::InvalidData`] if a key isn't 32 bytes, the signature isn't 64, the agreement
///   key is low order or not canonically encoded, or either signing key isn't a canonically
///   encoded, non-weak point.
#[uniffi::export]
pub fn verify_discovery_to_identity_binding(
    identity: IdentityKey,
    discovery_verifying_key: Vec<u8>,
    signature: Vec<u8>,
) -> Result<(), RoostError> {
    let identity = identity.to_core()?;
    if !is_valid_x25519_public_key(&identity.x25519_public_key) {
        return Err(invalid_key("identity x25519 public key"));
    }
    let identity_verifying_key = parse_ed25519_verifying_key_bytes(&identity.ed25519_verifying_key)
        .ok_or_else(|| invalid_key("identity ed25519 verifying key"))?;
    let discovery_verifying_key = parse_ed25519_verifying_key_bytes(&fixed_32(
        &discovery_verifying_key,
        "discovery ed25519 verifying key",
    )?)
    .ok_or_else(|| invalid_key("discovery ed25519 verifying key"))?;
    let signature =
        Signature::from_bytes(&fixed_64(&signature, "discovery to identity signature")?);
    Ok(crypto_verify_discovery_to_identity_binding(
        &PublicKey::from(identity.x25519_public_key),
        &identity_verifying_key,
        &discovery_verifying_key,
        &signature,
    )?)
}

fn invalid_key(label: &str) -> RoostError {
    RoostError::InvalidData {
        reason: format!("{label} is not a canonical, non-weak point"),
    }
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
    // The signature covers only the identity's two public halves, so the discovery key's other
    // fields and the identity's own binding signature take placeholder values.
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

    /// Both bindings sign the same 64 bytes, so only their contexts tell them apart.
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

        // The discovery key's signature must not pass as the identity's own binding either, even
        // under the discovery key that made it, so only the context rejects it.
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

    /// A relay answers a discovery key lookup with an identity of its own, correctly self-bound,
    /// that the typed discovery key never signed.
    #[test]
    fn a_substituted_identity_fails_against_the_typed_discovery_key() {
        let impostor = SigningKeyPair::from_signing_bytes(&[0x44; 32]);
        let impostor_identity = IdentityKey {
            agreement_key: IDENTITY_X25519.to_vec(),
            signing_key: impostor.verifying.to_bytes().to_vec(),
        };
        let self_binding = sign_identity_key_binding(&impostor, &IDENTITY_X25519.into()).unwrap();

        // The impostor's own binding verifies.
        verify_identity_key_binding(Identity {
            key: impostor_identity.clone(),
            binding_signature: self_binding.to_bytes().to_vec(),
        })
        .expect("a self-consistent impostor identity self-binds");

        // Only the discovery key's signature catches it.
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
            // A weak key verifies signatures nobody made, so a binding under one binds nothing.
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
