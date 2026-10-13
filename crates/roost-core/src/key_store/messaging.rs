use super::KeyStore;
use crate::protocol_state::LocalSenderKeys;
use crate::{
    DiscoveryKeyError, IdentityError, IncomingMessage, KeyStoreOperationError, LocalIdentityKeys,
    MessageDecryption, MessageEncryption, OutgoingMessage, ProtocolStateError,
    SignedSenderCertificate,
};

/// Errors returned when a Message Operation can't start.
#[derive(Debug, thiserror::Error)]
pub enum MessageStartError {
    /// Loading local discovery-key state failed.
    #[error(transparent)]
    Discovery(#[from] DiscoveryKeyError),
    /// Loading local identity state failed.
    #[error(transparent)]
    Identity(#[from] IdentityError),
    /// A committed KeyStore operation must be recovered before local keys can be used.
    #[error(transparent)]
    Operation(#[from] KeyStoreOperationError),
    /// The Message's inputs failed their checks.
    #[error(transparent)]
    ProtocolState(#[from] ProtocolStateError),
}

impl KeyStore {
    /// Starts encrypting a Message to a contact.
    ///
    /// The operation loads the local Identity's keys now and touches SecureStorage no more.
    /// Roost selects the Session and the contact's Discovery Key as the operation reads them.
    pub fn start_encryption(
        &self,
        message: OutgoingMessage,
    ) -> Result<MessageEncryption, MessageStartError> {
        let keys = {
            let _lifecycle = self.lifecycle_guard();
            self.ensure_no_recovery_required()?;
            self.load_local_identity_keys::<MessageStartError>()?
        };
        Ok(self.0.engine.start_encryption(keys, message)?)
    }

    /// Starts decrypting a received Message.
    ///
    /// The operation loads the local Identity's keys now and touches SecureStorage no more.
    pub fn start_decryption(
        &self,
        message: IncomingMessage,
    ) -> Result<MessageDecryption, MessageStartError> {
        let keys = {
            let _lifecycle = self.lifecycle_guard();
            self.ensure_no_recovery_required()?;
            self.load_local_identity_keys::<MessageStartError>()?
        };
        Ok(self.0.engine.start_decryption(keys, message)?)
    }

    // Loads the identity's key pairs and current Discovery Key, and both binding directions.
    pub(super) fn load_sender<E>(
        &self,
        certificate: &[u8],
        signature: &[u8],
    ) -> Result<LocalSenderKeys, E>
    where
        E: From<IdentityError> + From<DiscoveryKeyError> + From<ProtocolStateError>,
    {
        Ok(LocalSenderKeys::new(
            self.load_local_identity_keys::<E>()?,
            SignedSenderCertificate {
                certificate: certificate.to_vec(),
                signature: signature.to_vec(),
            },
        )?)
    }

    fn load_local_identity_keys<E: From<IdentityError> + From<DiscoveryKeyError>>(
        &self,
    ) -> Result<LocalIdentityKeys, E> {
        let (agreement_key, signing_key) = self.0.identity.load_key_pairs()?;
        Ok(LocalIdentityKeys {
            agreement_key,
            signing_key,
            discovery_key: self.0.discovery.current()?,
        })
    }
}
