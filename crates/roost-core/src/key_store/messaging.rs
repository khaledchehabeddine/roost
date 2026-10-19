use super::{KeyStore, KeyStoreError, KeyStoreOperationId};
use crate::protocol_state::{LocalIdentityKeys, SendIntent};
use crate::{
    DiscoveryKeyError, IdentityError, IncomingMessage, KeyStoreOperationError, MessageDecryption,
    MessageEncryption, MessageRecovery, OutgoingGrantUpdate, OutgoingMessage, OutgoingRecovery,
    ProtocolStateError,
};
use roost_crypto::{
    DiscoveryKey, OneTimePreKey, PublicSignedPreKey, SealedFramePreKeyReference, SignedPreKey,
};
use std::time::SystemTime;

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

/// The local prekeys a first Message names.
pub(crate) struct FirstMessagePreKeys {
    pub(crate) signed_prekey: SignedPreKey,
    pub(crate) one_time_prekey: Option<OneTimePreKey>,
    /// Every signed prekey this identity still holds, so Roost can forget deleted SessionIDs that
    /// no handshake can recreate.
    pub(crate) held_signed_prekeys: Vec<PublicSignedPreKey>,
}

impl KeyStore {
    /// Starts encrypting an ordinary Message to a contact.
    ///
    /// The operation loads the local Identity's keys now and touches SecureStorage no more.
    /// Roost selects the Session and the contact's Discovery Key as the operation reads them.
    pub fn start_encryption(
        &self,
        message: OutgoingMessage,
    ) -> Result<MessageEncryption, MessageStartError> {
        self.start_send(message, SendIntent::Message)
    }

    /// Starts encrypting a Contact Request, whose commit creates the contact's Pending record.
    ///
    /// A request to a contact who already asked sends a Contact Acceptance instead, and one to an
    /// accepted contact sends an ordinary Message.
    pub fn request_contact(
        &self,
        message: OutgoingMessage,
    ) -> Result<MessageEncryption, MessageStartError> {
        self.start_send(message, SendIntent::Request)
    }

    /// Starts encrypting a Contact Acceptance, whose commit accepts the contact.
    ///
    /// An acceptance to a contact already accepted sends an ordinary Message instead.
    pub fn accept_contact(
        &self,
        message: OutgoingMessage,
    ) -> Result<MessageEncryption, MessageStartError> {
        self.start_send(message, SendIntent::Acceptance)
    }

    /// Starts encrypting a Grant Update, which carries only the current Inbox Grant.
    ///
    /// The app picks who gets one and when, such as every contact after an inbox rotation, and
    /// Roost decides who may hold the grant. A blocked contact or a requester this side hasn't
    /// accepted is refused, and a contact that already acknowledged the current grant gets
    /// nothing. A requester's Grant Updates don't count toward the limit on Messages before
    /// acceptance.
    pub fn start_grant_update(
        &self,
        update: OutgoingGrantUpdate,
    ) -> Result<MessageEncryption, MessageStartError> {
        self.start_send(update.into_message(), SendIntent::GrantUpdate)
    }

    /// Starts one step of recovering a contact's unacknowledged Messages on a newer Session.
    ///
    /// The app runs steps as the recovery job a delivery check signaled, committing each resent
    /// Message, until one ends with nothing left to resend or waiting for the probe. The operation
    /// loads the local Identity's keys now and touches SecureStorage no more.
    pub fn start_recovery(
        &self,
        recovery: OutgoingRecovery,
    ) -> Result<MessageRecovery, MessageStartError> {
        let keys = self.message_keys()?;
        Ok(self.0.engine.start_recovery(keys, recovery)?)
    }

    fn start_send(
        &self,
        message: OutgoingMessage,
        intent: SendIntent,
    ) -> Result<MessageEncryption, MessageStartError> {
        let keys = self.message_keys()?;
        Ok(self.0.engine.start_encryption(keys, message, intent)?)
    }

    fn message_keys(&self) -> Result<LocalIdentityKeys, MessageStartError> {
        let _lifecycle = self.lifecycle_guard();
        self.ensure_no_recovery_required()?;
        self.load_local_identity_keys()
    }

    /// Starts decrypting a received Message.
    ///
    /// The operation loads the local Identity's keys and reads the clock now. It reads
    /// SecureStorage again only for the prekeys a first Message names, or the previous Discovery
    /// Key an established Message was sealed to before a rotation, and stages the use of a
    /// one-time prekey as a Prepared KeyStore Operation that travels in the result's state changes.
    pub fn start_decryption(
        &self,
        message: IncomingMessage,
    ) -> Result<MessageDecryption, MessageStartError> {
        let keys = self.message_keys()?;
        Ok(self
            .0
            .engine
            .start_decryption(self.clone(), SystemTime::now(), keys, message)?)
    }

    // Returns the Discovery Key a rotation replaced whose X25519 public key is `public_key`, while
    // the Relay may still hold Messages sealed to it at `now`.
    pub(crate) fn previous_discovery_key(
        &self,
        public_key: &[u8; 32],
        now: SystemTime,
    ) -> Result<Option<DiscoveryKey>, KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        Ok(self.0.discovery.previous_key(public_key, now)?)
    }

    // Returns the ID of the signed prekey a first Message names when it is one kept after a
    // rotation, which needs proof of admission, or `None` when it is the current one.
    pub(crate) fn signed_prekey_needing_admission(
        &self,
        epoch: u32,
        public_key: &[u8; 32],
        now: SystemTime,
    ) -> Result<Option<u64>, KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        let (signed_prekey, is_current) = self
            .0
            .signed_prekey
            .prekey_for_first_message(epoch, public_key, now)?;
        Ok((!is_current).then(|| signed_prekey.id()))
    }

    // Loads the signed and one-time prekeys a first Message names, without consuming either.
    pub(crate) fn first_message_prekeys(
        &self,
        reference: &SealedFramePreKeyReference,
        now: SystemTime,
    ) -> Result<FirstMessagePreKeys, KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        let (signed_prekey, _) = self.0.signed_prekey.prekey_for_first_message(
            reference.discovery_epoch,
            &reference.signed_prekey_public_key,
            now,
        )?;
        let one_time_prekey = reference
            .one_time_prekey
            .map(|prekey| {
                self.0.one_time_prekey.one_time_prekey_for_public_key(
                    reference.discovery_epoch,
                    prekey.id,
                    &prekey.public_key,
                )
            })
            .transpose()?;
        Ok(FirstMessagePreKeys {
            signed_prekey,
            one_time_prekey,
            held_signed_prekeys: self.0.signed_prekey.held_public(now)?,
        })
    }

    // Stages consuming the one-time prekey a new Session used, and returns the operation's ID.
    pub(crate) fn prepare_one_time_prekey_use(
        &self,
        epoch: u32,
        id: u64,
    ) -> Result<KeyStoreOperationId, KeyStoreError> {
        let prepared = self.prepare_operation(|staged| {
            staged
                .0
                .one_time_prekey
                .consume_one_time_prekey(epoch, id)
                .map_err(KeyStoreError::from)
        })?;
        Ok(prepared.id)
    }

    fn load_local_identity_keys(&self) -> Result<LocalIdentityKeys, MessageStartError> {
        let (agreement_key, signing_key) = self.0.identity.load_key_pairs()?;
        Ok(LocalIdentityKeys {
            agreement_key,
            signing_key,
            discovery_key: self.0.discovery.current()?,
            delivery_capability: self.0.discovery.current_capability()?,
        })
    }
}
