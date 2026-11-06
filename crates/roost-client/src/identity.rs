use crate::encoding::fixed_32;
use crate::error::RoostError;
use roost_core::{
    Identity as CoreIdentity, IdentityError, PublicIdentityKey as CorePublicIdentityKey,
};

/// An identity's public keys, safe to cache or send to peers.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct Identity {
    /// The identity key.
    pub key: IdentityKey,
    /// The signature that binds the identity key's agreement key to its signing key. Always 64
    /// bytes.
    pub binding_signature: Vec<u8>,
}

/// An identity's permanent public key, used for trust, certificates, and contacts.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct IdentityKey {
    /// The X25519 key that peers agree on shared secrets with. Always 32 bytes.
    pub agreement_key: Vec<u8>,
    /// The Ed25519 key that verifies the identity's signatures. Always 32 bytes.
    pub signing_key: Vec<u8>,
}

impl Identity {
    pub(crate) fn from_core(identity: CoreIdentity) -> Result<Self, IdentityError> {
        Ok(Self::from_public(identity.public()?))
    }

    pub(crate) fn from_public(public: CorePublicIdentityKey) -> Self {
        Self {
            key: IdentityKey {
                agreement_key: public.public_key.as_bytes().to_vec(),
                signing_key: public.verifying_key.as_bytes().to_vec(),
            },
            binding_signature: public.binding_signature.to_bytes().to_vec(),
        }
    }

    pub(crate) fn to_core(&self) -> Result<CorePublicIdentityKey, RoostError> {
        CorePublicIdentityKey::from_bytes(
            &self.key.agreement_key,
            &self.key.signing_key,
            &self.binding_signature,
        )
        .map_err(RoostError::from)
    }
}

impl IdentityKey {
    pub(crate) fn from_core(value: roost_core::IdentityKey) -> Self {
        Self {
            agreement_key: value.x25519_public_key.to_vec(),
            signing_key: value.ed25519_verifying_key.to_vec(),
        }
    }

    pub(crate) fn to_core(&self) -> Result<roost_core::IdentityKey, RoostError> {
        Ok(roost_core::IdentityKey {
            x25519_public_key: fixed_32(&self.agreement_key, "identity agreement key")?,
            ed25519_verifying_key: fixed_32(&self.signing_key, "identity signing key")?,
        })
    }
}
