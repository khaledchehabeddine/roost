//! UniFFI keystore object exposing identity, discovery-key, and signed-pre-key operations.

use crate::SecureStorage;
use crate::certificate::{
    SenderCertificateValidation, domain_signing_keys_to_core, revocation_state_to_core,
    revoked_identity_keys_to_core,
};
use crate::error::AetherError;
use crate::message::{Message, SenderIdentityMaterial};
use crate::protocol::{
    AcknowledgmentOutcome, IdentityKey as FfiIdentityKey, InboundMessageOutcome,
    OutboundMessageResult, ProtocolStateEntry, ProtocolStateUpdate, protocol_key,
    snapshot_input_from_entries, updates_from_core_absent,
};
use crate::records::{
    DiscoveryKeyBundle, Identity, OneTimePreKeyBundle, PublicationBundle, SignedPreKeyBundle,
    fixed_16, fixed_32,
};
use crate::storage::SecureStorageAdapter;
use aether_core::{
    AcknowledgmentProcessing, InboundSenderCertificateValidation, KeyStore as CoreKeyStore,
    MessageDecryption, MessageEncryption, MessageId, ProtocolStateKey, SessionAcceptance,
    SessionInitiation,
};
use std::sync::Arc;
use zeroize::Zeroizing;

/// Entry point for local identity, discovery-key, and signed-pre-key state.
///
/// Construct one keystore for the app and keep it for the process lifetime. Methods may be called
/// concurrently, but the keystore serializes access to the underlying [`SecureStorage`].
#[derive(uniffi::Object)]
pub struct KeyStore {
    inner: CoreKeyStore,
}

/// Result of starting a Session through X3DH.
#[derive(uniffi::Record)]
pub struct SessionInitiationResult {
    /// X3DH first Message to send after host commit.
    pub message: Message,
    /// Opaque protocol-state updates to commit.
    pub state_updates: Vec<ProtocolStateUpdate>,
}

/// Result of accepting a Session through X3DH.
#[derive(uniffi::Record)]
pub struct SessionAcceptanceResult {
    /// Decrypted first-message plaintext.
    pub plaintext: Vec<u8>,
    /// Sender identity material decoded after authentication.
    pub sender_identity: SenderIdentityMaterial,
    /// Opaque protocol-state updates to commit.
    pub state_updates: Vec<ProtocolStateUpdate>,
}

#[uniffi::export]
impl KeyStore {
    /// Constructs a keystore backed by the given platform [`SecureStorage`].
    ///
    /// No storage access or key generation occurs. Use [`Self::has_identity`] afterward to decide
    /// whether to generate or import an identity.
    ///
    /// # Examples
    /// ```
    /// use aether::{InMemorySecureStorage, KeyStore, SecureStorage};
    /// use std::sync::Arc;
    ///
    /// let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// let store = KeyStore::new(storage);
    /// ```
    #[uniffi::constructor]
    pub fn new(storage: Arc<dyn SecureStorage>) -> Arc<Self> {
        Arc::new(KeyStore {
            inner: CoreKeyStore::new(Box::new(SecureStorageAdapter::new(storage))),
        })
    }

    /// Generates a fresh identity (X25519 + Ed25519 key pairs) and persists it via
    /// [`SecureStorage`].
    ///
    /// # Examples
    /// ```
    /// # use aether::{AetherError, Identity, InMemorySecureStorage, KeyStore, SecureStorage};
    /// # use std::sync::Arc;
    /// # fn publish_identity(_identity: &Identity) -> Result<(), AetherError> { Ok(()) }
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = KeyStore::new(storage);
    /// let identity = store.generate_identity()?;
    /// publish_identity(&identity)?;
    /// # Ok::<(), AetherError>(())
    /// ```
    ///
    /// # Errors
    /// - [`AetherError::AlreadyExists`] if complete identity and discovery-key material already
    ///   exist.
    /// - [`AetherError::Corrupt`] if stored identity key material is incomplete.
    /// - [`AetherError::InternalError`] on storage lock poisoning or system clock anomaly.
    /// - [`AetherError::InvalidData`] if stored discovery-key or identity bytes are malformed.
    /// - [`AetherError::Storage`] if platform storage returns an error.
    pub fn generate_identity(&self) -> Result<Identity, AetherError> {
        Ok(Identity::from_core(self.inner.generate_identity()?)?)
    }

    /// Loads the stored identity's public material.
    ///
    /// # Examples
    /// ```
    /// # use aether::{AetherError, InMemorySecureStorage, KeyStore, SecureStorage};
    /// # use std::sync::Arc;
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = KeyStore::new(storage);
    /// # store.generate_identity()?;
    /// let identity = store.load_identity()?;
    /// # Ok::<(), AetherError>(())
    /// ```
    ///
    /// # Errors
    /// - [`AetherError::Corrupt`] if only one of the two key parts is present.
    /// - [`AetherError::InternalError`] on storage lock poisoning.
    /// - [`AetherError::InvalidData`] if a stored key has the wrong byte length.
    /// - [`AetherError::NotFound`] if no identity is stored.
    /// - [`AetherError::Storage`] on platform storage failure.
    pub fn load_identity(&self) -> Result<Identity, AetherError> {
        Ok(Identity::from_core(self.inner.load_identity()?)?)
    }

    /// Returns `true` when this keystore has identity data in storage.
    ///
    /// This is a presence check only. Use [`Self::load_identity`] to read and validate the public
    /// identity.
    ///
    /// # Examples
    /// ```
    /// # use aether::{AetherError, InMemorySecureStorage, KeyStore, SecureStorage};
    /// # use std::sync::Arc;
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = KeyStore::new(storage);
    /// if !store.has_identity()? {
    ///     store.generate_identity()?;
    /// }
    /// # Ok::<(), AetherError>(())
    /// ```
    ///
    /// # Errors
    /// - [`AetherError::InternalError`] on storage lock poisoning.
    /// - [`AetherError::Storage`] on platform storage failure.
    pub fn has_identity(&self) -> Result<bool, AetherError> {
        Ok(self.inner.has_identity()?)
    }

    /// Returns the currently stored signed pre-key bundle.
    ///
    /// Hand this to peers asking for the bundle they need to start a session.
    ///
    /// # Examples
    /// ```
    /// # use aether::{
    /// #     AetherError, InMemorySecureStorage, KeyStore, SecureStorage, SignedPreKeyBundle,
    /// # };
    /// # use std::sync::Arc;
    /// # fn send_bundle_to_peer(_bundle: &SignedPreKeyBundle) -> Result<(), AetherError> {
    /// #     Ok(())
    /// # }
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = KeyStore::new(storage);
    /// # store.generate_identity()?;
    /// # store.rotate_signed_prekey_if_stale()?;
    /// let bundle = store.current_signed_prekey_bundle()?;
    /// send_bundle_to_peer(&bundle)?;
    /// # Ok::<(), AetherError>(())
    /// ```
    ///
    /// # Errors
    /// - [`AetherError::InternalError`] on storage lock poisoning.
    /// - [`AetherError::InvalidData`] if the stored blob has the wrong length or unsupported
    ///   version.
    /// - [`AetherError::NotFound`] if no signed pre-key is stored.
    /// - [`AetherError::Storage`] on platform storage failure.
    pub fn current_signed_prekey_bundle(&self) -> Result<SignedPreKeyBundle, AetherError> {
        Ok(self.inner.current_signed_prekey_bundle()?.into())
    }

    /// Returns the current discovery-key bundle, verified against the identity key.
    ///
    /// Publish this alongside the signed pre-key bundle so peers can verify the trust chain.
    ///
    /// # Examples
    /// ```
    /// # use aether::{
    /// #     AetherError, DiscoveryKeyBundle, InMemorySecureStorage, KeyStore, SecureStorage
    /// # };
    /// # use std::sync::Arc;
    /// # fn send_to_peer(_bundle: &DiscoveryKeyBundle) -> Result<(), AetherError> {
    /// #     Ok(())
    /// # }
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = KeyStore::new(storage);
    /// # store.generate_identity()?;
    /// let bundle = store.current_discovery_key_bundle()?;
    /// send_to_peer(&bundle)?;
    /// # Ok::<(), AetherError>(())
    /// ```
    ///
    /// # Errors
    /// - [`AetherError::Corrupt`] if the stored discovery key does not verify or identity keys are
    ///   incomplete.
    /// - [`AetherError::InternalError`] on storage lock poisoning.
    /// - [`AetherError::InvalidData`] if stored discovery-key or identity bytes are malformed.
    /// - [`AetherError::NotFound`] if no identity or discovery key is stored.
    /// - [`AetherError::Storage`] on platform storage failure.
    pub fn current_discovery_key_bundle(&self) -> Result<DiscoveryKeyBundle, AetherError> {
        Ok(self.inner.current_discovery_key_bundle()?.into())
    }

    /// Returns the current publishable pair (discovery-key bundle + signed pre-key), atomically.
    ///
    /// Returns caller-created bundles that verify as a chain. Prefer this over reading the
    /// discovery-key and signed-pre-key bundles separately, which can race a concurrent rotation
    /// into a pair the peer rejects. Publish both bundles together.
    ///
    /// # Examples
    /// ```
    /// # use aether::{
    /// #     AetherError, InMemorySecureStorage, KeyStore, PublicationBundle, SecureStorage
    /// # };
    /// # use std::sync::Arc;
    /// # fn publish(_bundle: &PublicationBundle) -> Result<(), AetherError> {
    /// #     Ok(())
    /// # }
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = KeyStore::new(storage);
    /// # store.generate_identity()?;
    /// # store.rotate_signed_prekey_now()?;
    /// let publication = store.current_publication_bundle()?;
    /// publish(&publication)?;
    /// # Ok::<(), AetherError>(())
    /// ```
    ///
    /// # Errors
    /// - [`AetherError::Corrupt`] if stored key material does not verify as a chain.
    /// - [`AetherError::InternalError`] on storage lock poisoning or system clock anomaly.
    /// - [`AetherError::InvalidData`] if stored discovery-key, signed-pre-key, or identity bytes
    ///   are malformed.
    /// - [`AetherError::NotFound`] if no identity, discovery key, or signed pre-key is stored.
    /// - [`AetherError::Storage`] on platform storage failure.
    pub fn current_publication_bundle(&self) -> Result<PublicationBundle, AetherError> {
        Ok(self.inner.current_publication_bundle()?.into())
    }

    /// Generates exactly `batch_size` one-time pre-keys for the current discovery-key epoch.
    ///
    /// The returned records contain only public material. The secret halves remain in secure
    /// storage and are consumed by Rust when accepting a matching X3DH first message.
    ///
    /// # Errors
    /// - [`AetherError::InternalError`] on storage lock poisoning or system clock anomaly.
    /// - [`AetherError::InvalidData`] if stored one-time-pre-key data is malformed or the batch
    ///   exceeds capacity.
    /// - [`AetherError::NotFound`] if no identity or discovery key is stored.
    /// - [`AetherError::Storage`] on platform storage failure.
    pub fn generate_one_time_prekeys(
        &self,
        batch_size: u32,
    ) -> Result<Vec<OneTimePreKeyBundle>, AetherError> {
        Ok(self
            .inner
            .generate_one_time_prekeys(batch_size as usize)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Replenishes the one-time-prekey pool when it falls below the replenish threshold.
    ///
    /// Returns an empty list when the current pool is already above the threshold.
    ///
    /// # Errors
    /// - [`AetherError::InternalError`] on storage lock poisoning or system clock anomaly.
    /// - [`AetherError::InvalidData`] if stored one-time-prekey data is malformed.
    /// - [`AetherError::NotFound`] if no identity or discovery key is stored.
    /// - [`AetherError::Storage`] on platform storage failure.
    pub fn replenish_one_time_prekeys(&self) -> Result<Vec<OneTimePreKeyBundle>, AetherError> {
        Ok(self
            .inner
            .replenish_one_time_prekeys()?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Rotates the discovery key and signed pre-key together, returning both bundles.
    ///
    /// The discovery-key and signed-pre-key rotations are one operation. Stored one-time pre-keys
    /// are cleared before the discovery-key epoch advances. Publish both returned bundles together
    /// so peers can verify the full trust chain.
    ///
    /// # Examples
    /// ```
    /// # use aether::{
    /// #     AetherError, PublicationBundle, InMemorySecureStorage, KeyStore, SecureStorage,
    /// # };
    /// # use std::sync::Arc;
    /// # fn publish_rotation(_bundle: &PublicationBundle) -> Result<(), AetherError> {
    /// #     Ok(())
    /// # }
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = KeyStore::new(storage);
    /// # store.generate_identity()?;
    /// let rotation = store.rotate_discovery_key_now()?;
    /// publish_rotation(&rotation)?;
    /// # Ok::<(), AetherError>(())
    /// ```
    ///
    /// # Errors
    /// - [`AetherError::Corrupt`] if the discovery key cannot be verified while creating the
    ///   signed pre-key.
    /// - [`AetherError::InternalError`] on storage lock poisoning or system clock anomaly.
    /// - [`AetherError::InvalidData`] if stored discovery-key or identity bytes are malformed.
    /// - [`AetherError::NotFound`] if no identity is stored.
    /// - [`AetherError::Storage`] on platform storage failure.
    pub fn rotate_discovery_key_now(&self) -> Result<PublicationBundle, AetherError> {
        Ok(self.inner.rotate_discovery_key_now()?.into())
    }

    /// Rotates the signed pre-key if the stored one is missing or older than the rotation window.
    ///
    /// Returns the new bundle when rotation occurred, `None` when the stored signed pre-key is
    /// still fresh.
    ///
    /// Call once at app launch. The returned signed pre-key is signed by the current discovery
    /// key, so publish it together with that discovery-key bundle. Prefer
    /// [`Self::current_publication_bundle`] when publishing both keys. `None` means the stored
    /// signed pre-key is unchanged.
    ///
    /// # Examples
    /// ```
    /// # use aether::{
    /// #     AetherError, InMemorySecureStorage, KeyStore, SecureStorage, SignedPreKeyBundle,
    /// # };
    /// # use std::sync::Arc;
    /// # fn publish_signed_prekey_bundle(_bundle: &SignedPreKeyBundle) -> Result<(), AetherError> {
    /// #     Ok(())
    /// # }
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = KeyStore::new(storage);
    /// # store.generate_identity()?;
    /// if let Some(new_bundle) = store.rotate_signed_prekey_if_stale()? {
    ///     publish_signed_prekey_bundle(&new_bundle)?;
    /// }
    /// # Ok::<(), AetherError>(())
    /// ```
    ///
    /// # Errors
    /// - [`AetherError::Corrupt`] if the discovery key does not verify or identity keys are
    ///   incomplete.
    /// - [`AetherError::InternalError`] on storage lock poisoning or system clock anomaly.
    /// - [`AetherError::InvalidData`] if stored signed-pre-key, discovery-key, or identity bytes are
    ///   malformed.
    /// - [`AetherError::NotFound`] if no identity or discovery key is stored.
    /// - [`AetherError::Storage`] on platform storage failure.
    pub fn rotate_signed_prekey_if_stale(&self) -> Result<Option<SignedPreKeyBundle>, AetherError> {
        Ok(self.inner.rotate_signed_prekey_if_stale()?.map(Into::into))
    }

    /// Rotates the signed pre-key immediately, regardless of staleness, and returns the new
    /// bundle.
    ///
    /// Use when the caller needs a fresh bundle independent of the rotation window.
    ///
    /// # Examples
    /// ```
    /// # use aether::{
    /// #     AetherError, InMemorySecureStorage, KeyStore, SecureStorage, SignedPreKeyBundle,
    /// # };
    /// # use std::sync::Arc;
    /// # fn publish_signed_prekey_bundle(_bundle: &SignedPreKeyBundle) -> Result<(), AetherError> {
    /// #     Ok(())
    /// # }
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = KeyStore::new(storage);
    /// # store.generate_identity()?;
    /// let new_bundle = store.rotate_signed_prekey_now()?;
    /// publish_signed_prekey_bundle(&new_bundle)?;
    /// # Ok::<(), AetherError>(())
    /// ```
    ///
    /// # Errors
    /// - [`AetherError::Corrupt`] if the discovery key does not verify or identity keys are
    ///   incomplete.
    /// - [`AetherError::InternalError`] on storage lock poisoning or system clock anomaly.
    /// - [`AetherError::InvalidData`] if stored discovery-key or identity bytes are malformed.
    /// - [`AetherError::NotFound`] if no identity or discovery key is stored.
    /// - [`AetherError::Storage`] on platform storage failure.
    pub fn rotate_signed_prekey_now(&self) -> Result<SignedPreKeyBundle, AetherError> {
        Ok(self.inner.rotate_signed_prekey_now()?.into())
    }

    /// Starts a new Session as the initiator.
    ///
    /// Commit the returned state updates atomically with the returned Message before transport
    /// send. `session_key` is the host-chosen Session protocol-state key.
    ///
    /// # Errors
    /// - [`AetherError::AuthenticationFailed`] if X3DH, sealed-frame, sender-proof, or AEAD work
    ///   fails.
    /// - [`AetherError::InvalidData`] if key, message, certificate, or prekey inputs are malformed.
    /// - [`AetherError::NotFound`] if local identity or Discovery Key material is missing.
    /// - [`AetherError::ProtocolStateFault`] if install state cannot be encoded.
    /// - [`AetherError::Storage`] on platform storage failure.
    #[allow(clippy::too_many_arguments)]
    pub fn initiate_session(
        &self,
        session_key: Vec<u8>,
        responder_identity: Identity,
        responder_publication: PublicationBundle,
        responder_one_time_prekey: Option<OneTimePreKeyBundle>,
        sender_certificate: Vec<u8>,
        sender_signature: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> Result<SessionInitiationResult, AetherError> {
        let sender_certificate = Zeroizing::new(sender_certificate);
        let sender_signature = Zeroizing::new(sender_signature);
        let plaintext = Zeroizing::new(plaintext);
        let result = self.inner.initiate_session(SessionInitiation {
            session_key: ProtocolStateKey::from_bytes(session_key)?,
            responder_identity_key: responder_identity.to_core()?,
            responder_prekey_bundle: responder_publication
                .to_prekey_bundle(responder_one_time_prekey)?,
            sender_certificate: &sender_certificate,
            sender_signature: &sender_signature,
            plaintext: &plaintext,
        })?;
        Ok(SessionInitiationResult {
            message: Message::from_core(result.message),
            state_updates: updates_from_core_absent(result.state_updates)?,
        })
    }

    /// Accepts a new Session as the responder.
    ///
    /// A referenced one-time prekey is consumed only after the first Message authenticates.
    ///
    /// # Errors
    /// - [`AetherError::AuthenticationFailed`] if X3DH, sealed-frame, sender-proof, or AEAD work
    ///   fails.
    /// - [`AetherError::InvalidData`] if the message, key, or prekey inputs are malformed.
    /// - [`AetherError::NotFound`] if required local identity, Discovery Key, signed-prekey, or
    ///   one-time-prekey material is missing.
    /// - [`AetherError::ProtocolStateFault`] if install state cannot be encoded.
    /// - [`AetherError::Storage`] on platform storage failure.
    pub fn accept_session(
        &self,
        session_key: Vec<u8>,
        initiator_identity: Identity,
        message: Message,
    ) -> Result<SessionAcceptanceResult, AetherError> {
        let core_message = message.to_core()?;
        let result = self.inner.accept_session(SessionAcceptance {
            session_key: ProtocolStateKey::from_bytes(session_key)?,
            initiator_identity_key: initiator_identity.to_core()?,
            message: &core_message,
        })?;
        Ok(SessionAcceptanceResult {
            plaintext: result.plaintext.to_vec(),
            sender_identity: SenderIdentityMaterial::from_core(result.sender_identity),
            state_updates: updates_from_core_absent(result.state_updates)?,
        })
    }

    /// Encrypts an established-session Message using stored local identity signing material.
    ///
    /// Commit the returned state updates atomically with the returned Message before transport
    /// send.
    ///
    /// # Errors
    /// - [`AetherError::BlockedContact`] if the contact is locally blocked.
    /// - [`AetherError::InvalidData`] if message IDs, keys, or message fields are malformed.
    /// - [`AetherError::NotFound`] if local identity material is missing.
    /// - [`AetherError::ProtocolStateFault`] if required blobs are missing or malformed.
    /// - [`AetherError::Storage`] on platform storage failure.
    #[allow(clippy::too_many_arguments)]
    pub fn encrypt_message(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        session_key: Vec<u8>,
        message_id: Vec<u8>,
        contact_identity_key: FfiIdentityKey,
        recipient_public_key: Vec<u8>,
        timestamp_millis: u64,
        sender_certificate: Vec<u8>,
        sender_signature: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> Result<OutboundMessageResult, AetherError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        let sender_certificate = Zeroizing::new(sender_certificate);
        let sender_signature = Zeroizing::new(sender_signature);
        let plaintext = Zeroizing::new(plaintext);
        OutboundMessageResult::from_core(
            &snapshot,
            self.inner.encrypt_message(MessageEncryption {
                snapshot: &snapshot.snapshot,
                session_key: protocol_key(session_key)?,
                message_id: MessageId::from_bytes(fixed_16(&message_id, "message id")?),
                contact_identity_key: contact_identity_key.to_core()?,
                recipient_public_key: fixed_32(&recipient_public_key, "recipient public key")?,
                timestamp_millis,
                sender_certificate: &sender_certificate,
                sender_signature: &sender_signature,
                plaintext: &plaintext,
            })?,
        )
    }

    /// Decrypts an established-session Message and optionally returns an acknowledgment Message.
    ///
    /// Unique Messages require `sender_certificate_validation`; duplicates can return before
    /// validation because they surface no plaintext.
    ///
    /// # Errors
    /// - [`AetherError::AuthenticationFailed`] if sealed-sender, ratchet, transcript, or AEAD
    ///   authentication fails.
    /// - [`AetherError::CertificateRejected`] if sender-certificate validation rejects the sender.
    /// - [`AetherError::InvalidData`] if message IDs, keys, or message fields are malformed.
    /// - [`AetherError::ProtocolStateFault`] if required blobs are missing or malformed.
    /// - [`AetherError::Storage`] on platform storage failure.
    #[allow(clippy::too_many_arguments)]
    pub fn decrypt_message(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        session_key: Vec<u8>,
        deduplication_key: Vec<u8>,
        message: Message,
        acknowledgment_id: Vec<u8>,
        acknowledgment_recipient_public_key: Vec<u8>,
        acknowledgment_timestamp_millis: u64,
        acknowledgment_sender_certificate: Vec<u8>,
        acknowledgment_sender_signature: Vec<u8>,
        sender_certificate_validation: Option<SenderCertificateValidation>,
    ) -> Result<InboundMessageOutcome, AetherError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        let message = message.to_core()?;
        let acknowledgment_sender_certificate = Zeroizing::new(acknowledgment_sender_certificate);
        let acknowledgment_sender_signature = Zeroizing::new(acknowledgment_sender_signature);

        let validation_storage = if let Some(validation) = &sender_certificate_validation {
            Some((
                domain_signing_keys_to_core(&validation.domain_signing_keys)?,
                revoked_identity_keys_to_core(&validation.revocation_state)?,
            ))
        } else {
            None
        };
        let core_validation = sender_certificate_validation
            .as_ref()
            .zip(validation_storage.as_ref())
            .map(
                |(validation, (domain_signing_keys, revoked_identity_keys))| {
                    InboundSenderCertificateValidation {
                        domain_signing_keys,
                        revocation_state: revocation_state_to_core(
                            &validation.revocation_state,
                            revoked_identity_keys,
                        ),
                        reference_timestamp_secs: validation.reference_timestamp_secs,
                        grace_window_secs: validation.grace_window_secs,
                    }
                },
            );

        InboundMessageOutcome::from_core(
            &snapshot,
            self.inner.decrypt_message(MessageDecryption {
                snapshot: &snapshot.snapshot,
                session_key: protocol_key(session_key)?,
                deduplication_key: protocol_key(deduplication_key)?,
                message: &message,
                acknowledgment_id: MessageId::from_bytes(fixed_16(
                    &acknowledgment_id,
                    "acknowledgment id",
                )?),
                acknowledgment_recipient_public_key: fixed_32(
                    &acknowledgment_recipient_public_key,
                    "acknowledgment recipient public key",
                )?,
                acknowledgment_timestamp_millis,
                acknowledgment_sender_certificate: &acknowledgment_sender_certificate,
                acknowledgment_sender_signature: &acknowledgment_sender_signature,
                sender_certificate_validation: core_validation,
            })?,
        )
    }

    /// Processes an encrypted acknowledgment Message.
    ///
    /// Commit returned updates before clearing local transport retry state.
    ///
    /// # Errors
    /// - [`AetherError::AuthenticationFailed`] if sealed-sender, ratchet, transcript, or AEAD
    ///   authentication fails.
    /// - [`AetherError::InvalidData`] if message fields are malformed.
    /// - [`AetherError::ProtocolStateFault`] if required blobs are missing or malformed.
    /// - [`AetherError::Storage`] on platform storage failure.
    pub fn process_acknowledgment(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        session_key: Vec<u8>,
        message: Message,
    ) -> Result<AcknowledgmentOutcome, AetherError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        let message = message.to_core()?;
        AcknowledgmentOutcome::from_core(
            &snapshot,
            self.inner
                .process_acknowledgment(AcknowledgmentProcessing {
                    snapshot: &snapshot.snapshot,
                    session_key: protocol_key(session_key)?,
                    message: &message,
                })?,
        )
    }

    /// Exports the current identity and discovery key as a passphrase-encrypted blob.
    ///
    /// The blob is portable across devices: pass it to another keystore's
    /// [`Self::import_encrypted_backup`] with the same `passphrase` to restore the same identity
    /// and discovery-epoch lineage.
    ///
    /// Requires a stored discovery key; if it is missing, regenerate the identity with
    /// [`Self::generate_identity`] (which repairs the discovery key) before exporting.
    ///
    /// # Examples
    /// ```
    /// # use aether::{AetherError, InMemorySecureStorage, KeyStore, SecureStorage};
    /// # use std::sync::Arc;
    /// # fn persist_backup_blob(_blob: &[u8]) -> Result<(), AetherError> { Ok(()) }
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = KeyStore::new(storage);
    /// # store.generate_identity()?;
    /// let blob = store.export_encrypted_backup("strong passphrase".into())?;
    /// persist_backup_blob(&blob)?;
    /// # Ok::<(), AetherError>(())
    /// ```
    ///
    /// # Errors
    /// - [`AetherError::BackupFailed`] on randomness failure, Argon2id derivation error, or
    ///   authenticated encryption failure.
    /// - [`AetherError::Corrupt`] if identity keys are incomplete or the discovery key does not
    ///   verify against the current identity.
    /// - [`AetherError::InternalError`] on storage lock poisoning.
    /// - [`AetherError::InvalidData`] if a stored identity key has the wrong byte length.
    /// - [`AetherError::NotFound`] if no identity or discovery key is stored.
    /// - [`AetherError::Storage`] on platform storage failure when loading an identity.
    ///
    /// # Performance
    /// The backup blob is about 274 bytes: a versioned header carrying the Argon2id parameters,
    /// followed by the encrypted identity and discovery keys. Each call runs one Argon2id password
    /// hashing step using 64 MiB memory and 3 iterations.
    pub fn export_encrypted_backup(&self, passphrase: String) -> Result<Vec<u8>, AetherError> {
        let passphrase = Zeroizing::new(passphrase);
        Ok(self.inner.export_encrypted_backup(&passphrase)?)
    }

    /// Restores an identity from an encrypted backup, replacing any current identity.
    ///
    /// The backup is decrypted and the restored discovery key is validated against the restored
    /// identity before storage changes begin, so a wrong passphrase or malformed blob leaves the
    /// existing identity untouched. On success, the restored identity keeps the discovery key and
    /// epoch lineage carried by the backup and has no one-time pre-keys or signed pre-key. Restore
    /// does not restore protocol state; wipe or replace session, deduplication, and pending
    /// acknowledgment state, then use session recovery or re-handshake paths. Call
    /// [`Self::rotate_signed_prekey_if_stale`] before publishing.
    ///
    /// Storage failures can happen after writes begin and may leave incomplete key material. Call
    /// [`Self::reset`] before using the keystore again after a failed import.
    ///
    /// # Examples
    /// ```
    /// # use aether::{AetherError, InMemorySecureStorage, KeyStore, SecureStorage};
    /// # use std::sync::Arc;
    /// // Source keystore: generate an identity and export an encrypted backup.
    /// let source: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// let source_store = KeyStore::new(source);
    /// source_store.generate_identity()?;
    /// let blob = source_store.export_encrypted_backup("strong passphrase".into())?;
    ///
    /// // Restored keystore: import the blob into a fresh store.
    /// let destination: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// let destination_store = KeyStore::new(destination);
    /// destination_store.import_encrypted_backup(blob, "strong passphrase".into())?;
    /// # Ok::<(), AetherError>(())
    /// ```
    ///
    /// # Errors
    /// - [`AetherError::BackupFailed`] on Argon2id derivation failure.
    /// - [`AetherError::DecryptionFailed`] on wrong passphrase or backup authentication failure.
    /// - [`AetherError::InternalError`] on storage lock poisoning.
    /// - [`AetherError::Corrupt`] if the backup's discovery key is not signed by the backup's
    ///   identity key.
    /// - [`AetherError::InvalidData`] on a malformed header, authenticated unsupported version,
    ///   out-of-range Argon2id parameters, or a malformed discovery-key blob.
    /// - [`AetherError::Storage`] on platform storage failure during commit.
    ///
    /// # Performance
    /// The backup blob is about 274 bytes: a versioned header carrying the Argon2id parameters,
    /// followed by the encrypted identity and discovery keys. Each call runs one Argon2id password
    /// hashing step using 64 MiB memory and 3 iterations.
    pub fn import_encrypted_backup(
        &self,
        data: Vec<u8>,
        passphrase: String,
    ) -> Result<(), AetherError> {
        let data = Zeroizing::new(data);
        let passphrase = Zeroizing::new(passphrase);
        self.inner
            .import_encrypted_backup(data.as_slice(), passphrase.as_str())
            .map_err(Into::into)
    }

    /// Clears the stored one-time pre-keys, signed pre-key, discovery-key, and identity material.
    ///
    /// Deletion runs dependents-first, so a partial failure does not leave newer key material
    /// attached to a missing identity. Calling this on an empty store succeeds. Calling it again
    /// after a partial failure continues deleting any remaining keys.
    ///
    /// # Examples
    /// ```
    /// # use aether::{AetherError, InMemorySecureStorage, KeyStore, SecureStorage};
    /// # use std::sync::Arc;
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = KeyStore::new(storage);
    /// store.reset()?;
    /// # Ok::<(), AetherError>(())
    /// ```
    ///
    /// # Errors
    /// - [`AetherError::InternalError`] on storage lock poisoning.
    /// - [`AetherError::Storage`] on platform storage failure.
    pub fn reset(&self) -> Result<(), AetherError> {
        self.inner.reset().map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::KeyStore;
    use crate::{
        AetherError, InMemorySecureStorage, SecureStorage,
        protocol::{
            ContactDiscoveryKey, ContactIdentity, IdentityKey, ProtocolStateEngine,
            ProtocolStateEntry, ProtocolStateKind, ProtocolStateUpdate,
        },
        records::{
            DiscoveryKeyBundle as FfiDiscoveryKeyBundle, Identity as FfiIdentity,
            OneTimePreKeyBundle as FfiOneTimePreKeyBundle,
            PublicationBundle as FfiPublicationBundle, SignedPreKeyBundle as FfiSignedPreKeyBundle,
        },
    };
    use aether_crypto::{
        DiscoveryKeyBundle as CryptoDiscoveryKeyBundle,
        IdentityKeyBundle as CryptoIdentityKeyBundle, PublicKey, Signature,
        SignedPreKeyBundle as CryptoSignedPreKeyBundle, VerifyingKey, verify_discovery_key_bundle,
        verify_identity_key_bundle, verify_signed_prekey_bundle,
    };
    use std::sync::Arc;

    fn key_store() -> Arc<KeyStore> {
        let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
        KeyStore::new(storage)
    }

    fn verifying_key(identity: &FfiIdentity) -> VerifyingKey {
        VerifyingKey::from_bytes(
            &<[u8; 32]>::try_from(identity.ed25519_verifying_key.as_slice()).unwrap(),
        )
        .unwrap()
    }

    fn identity_bundle(identity: &FfiIdentity) -> CryptoIdentityKeyBundle {
        CryptoIdentityKeyBundle::from_bytes(
            &identity.x25519_public_key,
            &identity.ed25519_verifying_key,
            &identity.identity_binding_signature,
        )
        .unwrap()
    }

    fn discovery_bundle(bundle: &FfiDiscoveryKeyBundle) -> CryptoDiscoveryKeyBundle {
        CryptoDiscoveryKeyBundle::from_bytes(
            &bundle.public_key,
            &bundle.verifying_key,
            bundle.epoch,
            bundle.created_at,
            &bundle.signature,
        )
        .unwrap()
    }

    fn signed_prekey_bundle(bundle: &FfiSignedPreKeyBundle) -> CryptoSignedPreKeyBundle {
        CryptoSignedPreKeyBundle {
            public_key: PublicKey::from(
                <[u8; 32]>::try_from(bundle.public_key.as_slice()).unwrap(),
            ),
            signature: Signature::from_bytes(
                &<[u8; 64]>::try_from(bundle.signature.as_slice()).unwrap(),
            ),
            epoch: bundle.epoch,
            created_at: bundle.created_at,
        }
    }

    fn assert_discovery_key_verifies(
        identity: &FfiIdentity,
        discovery: &FfiDiscoveryKeyBundle,
    ) -> CryptoDiscoveryKeyBundle {
        let crypto_discovery = discovery_bundle(discovery);
        assert!(verify_discovery_key_bundle(&crypto_discovery, &verifying_key(identity)).is_ok());
        crypto_discovery
    }

    fn assert_signed_prekey_verifies(
        signed_prekey: &FfiSignedPreKeyBundle,
        discovery: &CryptoDiscoveryKeyBundle,
    ) {
        let crypto_prekey = signed_prekey_bundle(signed_prekey);
        assert!(verify_signed_prekey_bundle(&crypto_prekey, &discovery.verifying_key).is_ok());
    }

    fn assert_publication_verifies(identity: &FfiIdentity, publication: &FfiPublicationBundle) {
        assert_eq!(publication.version, aether_crypto::PREKEY_BUNDLE_VERSION);
        let discovery = assert_discovery_key_verifies(identity, &publication.discovery_key);
        assert_signed_prekey_verifies(&publication.signed_prekey, &discovery);
    }

    fn assert_one_time_prekey_record(bundle: &FfiOneTimePreKeyBundle, epoch: u32) {
        assert_eq!(bundle.public_key.len(), 32);
        assert_eq!(bundle.epoch, epoch);
    }

    fn identity_key(identity: &FfiIdentity) -> IdentityKey {
        IdentityKey {
            x25519_public_key: identity.x25519_public_key.clone(),
            ed25519_verifying_key: identity.ed25519_verifying_key.clone(),
        }
    }

    fn contact_identity(
        identity: &FfiIdentity,
        publication: &FfiPublicationBundle,
    ) -> ContactIdentity {
        ContactIdentity {
            identity_key: identity_key(identity),
            discovery_key: ContactDiscoveryKey {
                x25519_public_key: publication.discovery_key.public_key.clone(),
                ed25519_verifying_key: publication.discovery_key.verifying_key.clone(),
                epoch: publication.discovery_key.epoch,
                created_at: publication.discovery_key.created_at,
                identity_signature: publication.discovery_key.signature.clone(),
            },
        }
    }

    fn same_protocol_state_kind(left: ProtocolStateKind, right: ProtocolStateKind) -> bool {
        matches!(
            (left, right),
            (
                ProtocolStateKind::RatchetSession,
                ProtocolStateKind::RatchetSession
            ) | (ProtocolStateKind::PreKey, ProtocolStateKind::PreKey)
                | (
                    ProtocolStateKind::SenderCertificate,
                    ProtocolStateKind::SenderCertificate
                )
                | (
                    ProtocolStateKind::DeduplicationSet,
                    ProtocolStateKind::DeduplicationSet
                )
                | (
                    ProtocolStateKind::PendingAcknowledgments,
                    ProtocolStateKind::PendingAcknowledgments
                )
                | (
                    ProtocolStateKind::ContactState,
                    ProtocolStateKind::ContactState
                )
        )
    }

    fn apply_updates(entries: &mut Vec<ProtocolStateEntry>, updates: Vec<ProtocolStateUpdate>) {
        for update in updates {
            entries.retain(|entry| {
                !same_protocol_state_kind(entry.kind, update.kind) || entry.key != update.key
            });
            if let Some(blob) = update.blob {
                entries.push(ProtocolStateEntry {
                    kind: update.kind,
                    key: update.key,
                    blob,
                });
            }
        }
    }

    fn copy_snapshot(entries: &[ProtocolStateEntry]) -> Vec<ProtocolStateEntry> {
        entries
            .iter()
            .map(|entry| ProtocolStateEntry {
                kind: entry.kind,
                key: entry.key.clone(),
                blob: entry.blob.clone(),
            })
            .collect()
    }

    #[test]
    fn generate_identity_returns_ffi_safe_public_keys() {
        let store = key_store();
        let identity = store.generate_identity().unwrap();
        assert_eq!(identity.x25519_public_key.len(), 32);
        assert_eq!(identity.ed25519_verifying_key.len(), 32);
        assert_eq!(identity.identity_binding_signature.len(), 64);
        verifying_key(&identity);
        assert!(verify_identity_key_bundle(&identity_bundle(&identity)).is_ok());
    }

    #[test]
    fn rotate_signed_prekey_if_stale_returns_verifiable_record() {
        let store = key_store();
        let identity = store.generate_identity().unwrap();
        let signed_prekey = store
            .rotate_signed_prekey_if_stale()
            .unwrap()
            .expect("first rotate must produce a bundle");
        let discovery = store.current_discovery_key_bundle().unwrap();
        let crypto_discovery = assert_discovery_key_verifies(&identity, &discovery);
        assert_signed_prekey_verifies(&signed_prekey, &crypto_discovery);
    }

    #[test]
    fn current_publication_bundle_returns_verifiable_records() {
        let store = key_store();
        let identity = store.generate_identity().unwrap();
        store.rotate_signed_prekey_now().unwrap();
        let publication = store.current_publication_bundle().unwrap();
        assert_publication_verifies(&identity, &publication);
    }

    #[test]
    fn generate_one_time_prekeys_returns_public_records() {
        let store = key_store();
        store.generate_identity().unwrap();
        let discovery = store.current_discovery_key_bundle().unwrap();
        let bundles = store.generate_one_time_prekeys(3).unwrap();

        assert_eq!(bundles.len(), 3);
        assert_eq!(
            bundles.iter().map(|bundle| bundle.id).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        for bundle in &bundles {
            assert_one_time_prekey_record(bundle, discovery.epoch);
        }
    }

    #[test]
    fn rotate_discovery_key_now_advances_epoch_and_returns_verifiable_records() {
        let store = key_store();
        let identity = store.generate_identity().unwrap();
        let initial_discovery = store.current_discovery_key_bundle().unwrap();
        let rotation = store.rotate_discovery_key_now().unwrap();
        assert_eq!(rotation.discovery_key.epoch, initial_discovery.epoch + 1);
        assert_publication_verifies(&identity, &rotation);
    }

    #[test]
    fn replenish_one_time_prekeys_returns_public_records() {
        let store = key_store();
        store.generate_identity().unwrap();
        let discovery = store.current_discovery_key_bundle().unwrap();
        let bundles = store.replenish_one_time_prekeys().unwrap();

        assert_eq!(bundles.len(), 100);
        for bundle in &bundles {
            assert_one_time_prekey_record(bundle, discovery.epoch);
        }
        assert!(store.replenish_one_time_prekeys().unwrap().is_empty());
    }

    #[test]
    fn session_establishment_round_trips_first_message_through_ffi_records() {
        let alice = key_store();
        let bob = key_store();
        let alice_identity = alice.generate_identity().unwrap();
        let bob_identity = bob.generate_identity().unwrap();
        bob.rotate_signed_prekey_now().unwrap();
        let bob_publication = bob.current_publication_bundle().unwrap();
        let bob_one_time_prekey = bob.generate_one_time_prekeys(1).unwrap().remove(0);

        let session_key = vec![0x44; 16];
        let initiation = alice
            .initiate_session(
                session_key.clone(),
                bob_identity,
                bob_publication,
                Some(bob_one_time_prekey),
                b"alice certificate".to_vec(),
                b"alice signature".to_vec(),
                b"hello bob".to_vec(),
            )
            .unwrap();

        assert!(initiation.message.prekey_reference.is_some());
        assert_eq!(initiation.state_updates.len(), 2);

        let acceptance = bob
            .accept_session(session_key, alice_identity, initiation.message)
            .unwrap();

        assert_eq!(acceptance.plaintext, b"hello bob".to_vec());
        assert_eq!(
            acceptance.sender_identity.certificate,
            b"alice certificate".to_vec()
        );
        assert_eq!(acceptance.state_updates.len(), 2);
    }

    #[test]
    fn encrypt_message_returns_message_and_pending_state_update() {
        let alice = key_store();
        let bob = key_store();
        let alice_identity = alice.generate_identity().unwrap();
        let bob_identity = bob.generate_identity().unwrap();
        bob.rotate_signed_prekey_now().unwrap();
        let bob_publication = bob.current_publication_bundle().unwrap();
        let bob_one_time_prekey = bob.generate_one_time_prekeys(1).unwrap().remove(0);
        let session_key = vec![0x55; 16];
        let initiation = alice
            .initiate_session(
                session_key.clone(),
                bob_identity.clone(),
                bob_publication.clone(),
                Some(bob_one_time_prekey),
                b"alice certificate".to_vec(),
                b"alice signature".to_vec(),
                b"hello bob".to_vec(),
            )
            .unwrap();
        let acceptance = bob
            .accept_session(
                session_key.clone(),
                alice_identity,
                initiation.message.clone(),
            )
            .unwrap();

        let engine = ProtocolStateEngine::new();
        let mut alice_snapshot = Vec::new();
        apply_updates(&mut alice_snapshot, initiation.state_updates);
        let change = engine
            .record_contact(
                Vec::new(),
                contact_identity(&bob_identity, &bob_publication),
            )
            .unwrap();
        apply_updates(&mut alice_snapshot, change.state_updates);
        let accepted = engine
            .accept_contact(copy_snapshot(&alice_snapshot), identity_key(&bob_identity))
            .unwrap();
        apply_updates(&mut alice_snapshot, accepted.state_updates);

        let outbound = alice
            .encrypt_message(
                copy_snapshot(&alice_snapshot),
                session_key.clone(),
                vec![0x77; 16],
                identity_key(&bob_identity),
                bob_publication.discovery_key.public_key,
                42,
                b"alice certificate".to_vec(),
                b"alice signature".to_vec(),
                b"follow-up".to_vec(),
            )
            .unwrap();

        assert_eq!(outbound.message_id, vec![0x77; 16]);
        assert_eq!(outbound.state_updates.len(), 2);
        apply_updates(&mut alice_snapshot, outbound.state_updates);
        let pending = engine
            .pending_acknowledgments(alice_snapshot, session_key)
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(acceptance.plaintext, b"hello bob".to_vec());
    }

    #[test]
    fn decrypt_message_requires_certificate_validation_for_unique_message() {
        let alice = key_store();
        let bob = key_store();
        let alice_identity = alice.generate_identity().unwrap();
        let bob_identity = bob.generate_identity().unwrap();
        alice.rotate_signed_prekey_now().unwrap();
        bob.rotate_signed_prekey_now().unwrap();
        let alice_publication = alice.current_publication_bundle().unwrap();
        let bob_publication = bob.current_publication_bundle().unwrap();
        let bob_one_time_prekey = bob.generate_one_time_prekeys(1).unwrap().remove(0);
        let session_key = vec![0x66; 16];
        let initiation = alice
            .initiate_session(
                session_key.clone(),
                bob_identity.clone(),
                bob_publication.clone(),
                Some(bob_one_time_prekey),
                b"alice certificate".to_vec(),
                b"alice signature".to_vec(),
                b"hello bob".to_vec(),
            )
            .unwrap();
        let acceptance = bob
            .accept_session(
                session_key.clone(),
                alice_identity.clone(),
                initiation.message,
            )
            .unwrap();

        let engine = ProtocolStateEngine::new();
        let mut alice_snapshot = Vec::new();
        apply_updates(&mut alice_snapshot, initiation.state_updates);
        let change = engine
            .record_contact(
                Vec::new(),
                contact_identity(&bob_identity, &bob_publication),
            )
            .unwrap();
        apply_updates(&mut alice_snapshot, change.state_updates);
        let accepted = engine
            .accept_contact(copy_snapshot(&alice_snapshot), identity_key(&bob_identity))
            .unwrap();
        apply_updates(&mut alice_snapshot, accepted.state_updates);
        let outbound = alice
            .encrypt_message(
                alice_snapshot,
                session_key.clone(),
                vec![0x88; 16],
                identity_key(&bob_identity),
                bob_publication.discovery_key.public_key,
                43,
                b"alice certificate".to_vec(),
                b"alice signature".to_vec(),
                b"follow-up".to_vec(),
            )
            .unwrap();

        let mut bob_snapshot = Vec::new();
        apply_updates(&mut bob_snapshot, acceptance.state_updates);
        let deduplication_key = b"bob-dedup".to_vec();
        apply_updates(
            &mut bob_snapshot,
            vec![
                engine
                    .initialize_deduplication_set(deduplication_key.clone())
                    .unwrap(),
            ],
        );
        let result = bob.decrypt_message(
            bob_snapshot,
            session_key,
            deduplication_key,
            outbound.message,
            vec![0x99; 16],
            alice_publication.discovery_key.public_key,
            44,
            b"bob certificate".to_vec(),
            b"bob signature".to_vec(),
            None,
        );

        match result {
            Err(AetherError::InvalidData { .. }) => {}
            Err(error) => panic!("expected InvalidData, got {error}"),
            Ok(_) => panic!("expected InvalidData"),
        }
    }
}
