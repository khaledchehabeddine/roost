//! UniFFI keystore object exposing identity, discovery-key, and signed-pre-key operations.

use crate::SecureStorage;
use crate::certificate::{
    SenderCertificateValidation, domain_signing_keys_to_core, revocation_state_to_core,
    revoked_identity_keys_to_core,
};
use crate::error::AetherError;
use crate::message::{Message, SenderIdentityMaterial};
use crate::protocol::{
    AcknowledgmentOutcome, ContactStateChange, IdentityKey as FfiIdentityKey,
    InboundMessageOutcome, OutboundMessageResult, ProtocolStateEntry, ProtocolStateUpdate,
    protocol_key, snapshot_input_from_entries, updates_from_core_absent,
};
use crate::records::{
    DiscoveryKeyBundle, Identity, InboxRotation, OneTimePreKeyBundle, PublicationBundle,
    SignedPreKeyBundle, fixed_16, fixed_32,
};
use crate::storage::SecureStorageAdapter;
use aether_core::{
    AcknowledgmentProcessing, InboundSenderCertificateValidation, KeyStore as CoreKeyStore,
    MessageDecryption, MessageEncryption, MessageId, ProtocolStateKey, SessionAcceptance,
    SessionInitiation,
};
use std::sync::Arc;
use zeroize::Zeroizing;

/// Largest authentication transcript this keystore will sign, in bytes.
///
/// A relay authentication transcript is 159 bytes for the HTTP form and 120 for the WebSocket
/// form, so this leaves room for long request targets while keeping the export from doubling as a
/// bulk document signer.
const MAX_AUTHENTICATION_TRANSCRIPT_LEN: usize = 4096;

/// ASCII prefix reserved for preimages Aether signs or verifies itself.
///
/// Every context and domain tag in `docs/domain-separation.md` starts with these bytes, so
/// refusing them keeps [`KeyStore::sign_authentication_transcript`] disjoint from the whole
/// registry. Matched case-insensitively to cover the lowercase hash-domain convention as well.
const RESERVED_AETHER_DOMAIN_PREFIX: &[u8] = b"Aether";

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

/// Result of blocking a contact.
#[derive(uniffi::Record)]
pub struct ContactBlock {
    /// Contact state change to commit durably, then emit.
    pub contact: ContactStateChange,
    /// The inbox rotation the block performed, absent when the contact was already blocked.
    ///
    /// Present means every remaining contact now holds a stale delivery capability and must be
    /// given the new one before it can reach this inbox again. The blocked contact is deliberately
    /// not among them — that is what makes the block bite at the relay rather than only locally.
    pub rotation: Option<InboxRotation>,
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

    /// Signs a caller-built authentication transcript with the identity key's Ed25519 half.
    ///
    /// The transcript is signed exactly as given — no context is prepended. Callers own their own
    /// domain separation and put it inside the transcript, which is what a relay authentication
    /// transcript already does: `Relay-HTTP-Auth-v1` and `Relay-WebSocket-Auth-v1` are literal
    /// prefixes of the bytes the relay rebuilds and verifies. Prepending a second context here
    /// would produce a preimage no verifier ever reconstructs, so this operation deliberately does
    /// not. Aether defines neither the transcript layout nor the verifier, and never inspects the
    /// fields.
    ///
    /// What Aether does enforce is that the result can never be mistaken for one of its own
    /// signatures. A transcript starting with the reserved ASCII prefix `Aether`, matched
    /// case-insensitively, is refused, because every preimage Aether signs or verifies begins with
    /// a context from `docs/domain-separation.md` and every one of those begins with those bytes.
    /// Without the check this export would be a signing oracle able to mint an identity binding, a
    /// discovery-to-identity binding, or a message-transcript signature under the local identity
    /// key from bytes the caller — or whoever supplies the caller — chose.
    ///
    /// Returns the 64 signature bytes. Ed25519 signing is deterministic, so an identical
    /// transcript always yields an identical signature.
    ///
    /// # Examples
    /// ```
    /// # use aether::{AetherError, InMemorySecureStorage, KeyStore, SecureStorage};
    /// # use std::sync::Arc;
    /// # fn challenge_nonce() -> [u8; 32] { [0x22; 32] }
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = KeyStore::new(storage);
    /// # store.generate_identity()?;
    /// let identity = store.load_identity()?;
    ///
    /// // The caller builds the whole preimage, context included.
    /// let mut transcript = b"Relay-WebSocket-Auth-v1".to_vec();
    /// transcript.extend_from_slice(&1u16.to_be_bytes());
    /// transcript.extend_from_slice(&challenge_nonce());
    /// transcript.extend_from_slice(&identity.ed25519_verifying_key);
    ///
    /// let signature = store.sign_authentication_transcript(transcript)?;
    /// assert_eq!(signature.len(), 64);
    /// # Ok::<(), AetherError>(())
    /// ```
    ///
    /// # Errors
    /// - [`AetherError::Corrupt`] if only one of the two stored identity key parts is present.
    /// - [`AetherError::InternalError`] on storage lock poisoning.
    /// - [`AetherError::InvalidData`] if the transcript is empty, longer than 4096 bytes, starts
    ///   with the reserved `Aether` prefix, or a stored identity key has the wrong byte length.
    /// - [`AetherError::NotFound`] if no identity is stored.
    /// - [`AetherError::Storage`] on platform storage failure.
    pub fn sign_authentication_transcript(
        &self,
        transcript: Vec<u8>,
    ) -> Result<Vec<u8>, AetherError> {
        let transcript = Zeroizing::new(transcript);
        check_signable_transcript(&transcript)?;
        Ok(self
            .inner
            .load_identity()?
            .sign(&transcript)
            .to_bytes()
            .to_vec())
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

    /// Returns the recipient delivery capability for the current inbox generation. Always 32
    /// bytes.
    ///
    /// This is a bearer secret. Give it only to authorized contacts over an encrypted channel and
    /// persist it in platform secure storage. Register
    /// [`PublicationBundle::recipient_delivery_verifier`] with the relay instead — Aether never
    /// registers, validates, or transmits a capability.
    ///
    /// # Errors
    /// - [`AetherError::InternalError`] on storage lock poisoning.
    /// - [`AetherError::InvalidData`] if the stored discovery-key blob is malformed.
    /// - [`AetherError::NotFound`] if no discovery key is stored.
    /// - [`AetherError::Storage`] on platform storage failure.
    pub fn current_delivery_capability(&self) -> Result<Vec<u8>, AetherError> {
        Ok(self
            .inner
            .current_delivery_capability()?
            .to_bytes()
            .to_vec())
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
    /// let rotation = store.rotate_inbox_now()?;
    /// publish_rotation(&rotation.publication)?;
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
    pub fn rotate_inbox_now(&self) -> Result<InboxRotation, AetherError> {
        let rotation = self.inner.rotate_inbox_now()?;
        Ok(InboxRotation {
            publication: rotation.publication.into(),
            capability: rotation.capability.to_bytes().to_vec(),
        })
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

    /// Blocks a contact and rotates the inbox so the block takes effect at the relay.
    ///
    /// [`crate::ProtocolStateEngine::block_contact`] changes local state only, which stops this
    /// device sending and surfacing that contact's messages but leaves the contact holding a
    /// working delivery capability — it can still reach the relay and queue messages. Rotating
    /// invalidates that capability, at the cost of invalidating every *other* contact's copy too:
    /// when [`ContactBlock::rotation`] is present, each remaining contact must be given the new
    /// capability before it can deliver again. [`crate::ProtocolStateEngine::
    /// contacts_needing_inbox_authorization`] returns exactly that list, and excludes the blocked
    /// contact.
    ///
    /// Blocking an already-blocked contact performs no rotation, so repeating the call does not
    /// churn every contact's capability.
    ///
    /// # Errors
    /// - [`AetherError::InvalidData`] if `identity_key` has the wrong length.
    /// - [`AetherError::InternalError`] on storage lock poisoning or system clock anomaly.
    /// - [`AetherError::ProtocolStateFault`] if no contact is stored for `identity_key`, or its
    ///   blob is malformed.
    /// - [`AetherError::Storage`] on platform storage failure.
    pub fn block_contact(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        identity_key: FfiIdentityKey,
    ) -> Result<ContactBlock, AetherError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        let blocked = self
            .inner
            .block_contact(&snapshot.snapshot, identity_key.to_core()?)?;
        Ok(ContactBlock {
            contact: ContactStateChange::from_core(&snapshot, blocked.contact)?,
            rotation: blocked.rotation.map(|rotation| InboxRotation {
                publication: rotation.publication.into(),
                capability: rotation.capability.to_bytes().to_vec(),
            }),
        })
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
    #[expect(
        clippy::too_many_arguments,
        reason = "flat UniFFI export preserves generated binding shape"
    )]
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
            responder_discovery_to_identity: responder_publication
                .discovery_to_identity_signature()?,
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
        initiator_identity: Option<Identity>,
        message: Message,
    ) -> Result<SessionAcceptanceResult, AetherError> {
        let core_message = message.to_core()?;
        let initiator_identity_key = initiator_identity
            .map(|identity| identity.to_core())
            .transpose()?;
        let result = self.inner.accept_session(SessionAcceptance {
            session_key: ProtocolStateKey::from_bytes(session_key)?,
            initiator_identity_key,
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
    #[expect(
        clippy::too_many_arguments,
        reason = "flat UniFFI export preserves generated binding shape"
    )]
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
    #[expect(
        clippy::too_many_arguments,
        reason = "flat UniFFI export preserves generated binding shape"
    )]
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
                        expected_relay_domain: &validation.expected_relay_domain,
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

// Bounds what the identity key will sign for a caller-defined purpose. The prefix rule is the
// security-relevant half: it keeps this export's preimages disjoint from every context in
// docs/domain-separation.md, so no signature it produces can satisfy an Aether verifier.
fn check_signable_transcript(transcript: &[u8]) -> Result<(), AetherError> {
    if transcript.is_empty() {
        return Err(AetherError::InvalidData {
            reason: "authentication transcript is empty".into(),
        });
    }
    if transcript.len() > MAX_AUTHENTICATION_TRANSCRIPT_LEN {
        return Err(AetherError::InvalidData {
            reason: format!(
                "authentication transcript exceeds {MAX_AUTHENTICATION_TRANSCRIPT_LEN} bytes"
            ),
        });
    }
    let reserved = RESERVED_AETHER_DOMAIN_PREFIX.len();
    if transcript.len() >= reserved
        && transcript[..reserved].eq_ignore_ascii_case(RESERVED_AETHER_DOMAIN_PREFIX)
    {
        return Err(AetherError::InvalidData {
            reason: "authentication transcript starts with the reserved Aether domain prefix"
                .into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{KeyStore, MAX_AUTHENTICATION_TRANSCRIPT_LEN};
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
        IdentityKeyBundle as CryptoIdentityKeyBundle, PublicKey,
        RecipientDeliveryCapability as CryptoCapability, Signature,
        SignedPreKeyBundle as CryptoSignedPreKeyBundle, SigningKeyPair, VerifyingKey,
        verify_discovery_key_bundle, verify_discovery_to_identity_binding,
        verify_identity_key_bundle, verify_signed_prekey_bundle, verify_with_context,
    };
    use std::sync::Arc;

    /// Every Ed25519 signature context and canonical-encoding domain tag in
    /// `docs/domain-separation.md`, plus the one lowercase hash domain, as of v0.11.0.
    const AETHER_DOMAIN_REGISTRY: [&str; 10] = [
        "AetherIKBinding-v1:",
        "AetherDK-v1:",
        "AetherDKToIK-v1:",
        "AetherSPK-v1:",
        "AetherMessageTranscript-v1:",
        "AetherIK-v1:",
        "AetherSafetyNumber-v1:",
        "AetherSenderCertificate-v2:",
        "AetherProtocolStateCommit-v1:",
        "aether-recipient-delivery-capability-v1",
    ];

    const RELAY_HTTP_AUTH_CONTEXT: &[u8] = b"Relay-HTTP-Auth-v1";
    const RELAY_PROTOCOL_VERSION: u16 = 1;
    const REL_RLY_18_KAT_IDENTITY_SIGNING_SECRET: [u8; 32] = [0x11; 32];
    const REL_RLY_18_KAT_CHALLENGE_NONCE: [u8; 32] = [0x22; 32];
    const REL_RLY_18_KAT_RELAY_DOMAIN: &[u8] = b"relay.example";
    const REL_RLY_18_KAT_METHOD: &[u8] = b"POST";
    const REL_RLY_18_KAT_REQUEST_TARGET: &[u8] = b"/v1/prekeys?count=10";
    const REL_RLY_18_KAT_BODY_DIGEST_HEX: &str =
        "5e7ea43567be4f0a65821dcdfa31d2d92cb0d0d666df62b7f6cdaacac19d4047";
    const REL_RLY_18_KAT_TRANSCRIPT_LEN: usize = 159;
    const REL_RLY_18_KAT_EXPECTED_VERIFYING_HEX: &str =
        "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
    const REL_RLY_18_KAT_EXPECTED_SIGNATURE_HEX: &str = "7925dfac93637e618b5fad03a236f2c1\
         f0a913b252c79ac594123a40a00a2929\
         951d1a452bafccc602baf9072ff42105\
         07e53969e62220f2e2fea9d9713d340c";

    fn hex32(hex: &str) -> [u8; 32] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    fn push_length_prefixed(transcript: &mut Vec<u8>, field: &[u8]) {
        transcript.extend_from_slice(&(field.len() as u16).to_be_bytes());
        transcript.extend_from_slice(field);
    }

    // REL-RLY-16: concat("Relay-HTTP-Auth-v1", protocol_version_u16_be, challenge_nonce,
    // identity_signing_key, len_u16_be(relay_domain), relay_domain, len_u16_be(method), method,
    // len_u16_be(request_target), request_target, SHA-256(request_body)). Fixed-width fields and
    // the context itself carry no length prefix, and nothing separates the context from what
    // follows it.
    fn relay_http_transcript(identity_signing_key: &[u8], body_digest: &[u8; 32]) -> Vec<u8> {
        let mut transcript = RELAY_HTTP_AUTH_CONTEXT.to_vec();
        transcript.extend_from_slice(&RELAY_PROTOCOL_VERSION.to_be_bytes());
        transcript.extend_from_slice(&REL_RLY_18_KAT_CHALLENGE_NONCE);
        transcript.extend_from_slice(identity_signing_key);
        push_length_prefixed(&mut transcript, REL_RLY_18_KAT_RELAY_DOMAIN);
        push_length_prefixed(&mut transcript, REL_RLY_18_KAT_METHOD);
        push_length_prefixed(&mut transcript, REL_RLY_18_KAT_REQUEST_TARGET);
        transcript.extend_from_slice(body_digest);
        transcript
    }

    fn signature_from(bytes: &[u8]) -> Signature {
        Signature::from_bytes(&<[u8; 64]>::try_from(bytes).unwrap())
    }

    /// Known-answer test for the REL-RLY-16 authentication transcript and the signature over it.
    ///
    /// Source: Relay REL-RLY-18 published vector (`relay/docs/auth-transcript.md`), produced by
    /// the relay's own transcript encoder and `ed25519-dalek` verifier, which share no code with
    /// this crate. Matching the expected signature pins all 159 transcript bytes, because any
    /// difference in field order, length prefixing, or separators changes the signature.
    ///
    /// Inputs:
    /// - `identity_signing_secret = REL_RLY_18_KAT_IDENTITY_SIGNING_SECRET`
    /// - `challenge_nonce = REL_RLY_18_KAT_CHALLENGE_NONCE`
    /// - `relay_domain = REL_RLY_18_KAT_RELAY_DOMAIN`
    /// - `protocol_version = RELAY_PROTOCOL_VERSION`
    /// - `method = REL_RLY_18_KAT_METHOD`
    /// - `request_target = REL_RLY_18_KAT_REQUEST_TARGET`
    /// - `body_digest = REL_RLY_18_KAT_BODY_DIGEST_HEX` (SHA-256 of `b"vector-body"`)
    ///
    /// Derivation:
    /// ```text
    /// transcript = concat("Relay-HTTP-Auth-v1", protocol_version, challenge_nonce,
    ///                     identity_signing_key, len(relay_domain), relay_domain, len(method),
    ///                     method, len(request_target), request_target, body_digest)
    /// signature = Ed25519-Sign(identity_signing_secret, transcript)
    /// ```
    ///
    /// Output:
    /// - `identity_signing_key = REL_RLY_18_KAT_EXPECTED_VERIFYING_HEX`
    /// - `signature = REL_RLY_18_KAT_EXPECTED_SIGNATURE_HEX`
    #[test]
    fn relay_http_authentication_transcript_signature_known_answer() {
        let signing = SigningKeyPair::from_signing_bytes(REL_RLY_18_KAT_IDENTITY_SIGNING_SECRET);
        assert_eq!(
            hex::encode(signing.verifying.to_bytes()),
            REL_RLY_18_KAT_EXPECTED_VERIFYING_HEX
        );

        let transcript = relay_http_transcript(
            signing.verifying.as_bytes(),
            &hex32(REL_RLY_18_KAT_BODY_DIGEST_HEX),
        );

        assert_eq!(transcript.len(), REL_RLY_18_KAT_TRANSCRIPT_LEN);
        assert_eq!(
            hex::encode(signing.sign(&transcript).to_bytes()),
            REL_RLY_18_KAT_EXPECTED_SIGNATURE_HEX
        );
    }

    /// The signature must cover the transcript bytes and nothing else.
    ///
    /// The relay rebuilds the transcript alone and calls bare Ed25519 verify, so a context
    /// prepended on this side — what `sign_with_context` would do — yields a preimage the relay
    /// never reconstructs. That failure is silent at the boundary and only shows up as a signature
    /// that verifies nowhere, which is why it is pinned here rather than left to the caller.
    #[test]
    fn signed_authentication_transcript_verifies_bare_and_is_not_context_prefixed() {
        let store = key_store();
        let identity = store.generate_identity().unwrap();
        let transcript = relay_http_transcript(
            &identity.ed25519_verifying_key,
            &hex32(REL_RLY_18_KAT_BODY_DIGEST_HEX),
        );

        let signature_bytes = store
            .sign_authentication_transcript(transcript.clone())
            .unwrap();

        assert_eq!(signature_bytes.len(), 64);
        let signature = signature_from(&signature_bytes);
        let verifying = verifying_key(&identity);
        assert!(verifying.verify_strict(&transcript, &signature).is_ok());
        // Re-prepending the transcript's own context is the exact shape a contextual signature
        // would have had. It must not verify, or this export would be signing the wrong preimage.
        assert!(
            verify_with_context(&verifying, RELAY_HTTP_AUTH_CONTEXT, &transcript, &signature)
                .is_err()
        );
        for context in AETHER_DOMAIN_REGISTRY {
            assert!(
                verify_with_context(&verifying, context.as_bytes(), &transcript, &signature)
                    .is_err()
            );
        }
        // Ed25519 is deterministic, so a host retrying the same challenge resends the same proof.
        assert_eq!(
            store.sign_authentication_transcript(transcript).unwrap(),
            signature_bytes
        );
    }

    /// An unrestricted "sign these bytes with the identity key" export would be a signing oracle
    /// over Aether's own preimages: the identity key is what signs identity bindings,
    /// discovery-key bindings, and message transcripts. Every context Aether signs or verifies
    /// under starts with `Aether`, so refusing that prefix makes the two preimage sets disjoint.
    #[test]
    fn sign_authentication_transcript_refuses_reserved_aether_preimages() {
        let store = key_store();
        let identity = store.generate_identity().unwrap();

        for context in AETHER_DOMAIN_REGISTRY {
            let mut preimage = context.as_bytes().to_vec();
            preimage.extend_from_slice(&identity.x25519_public_key);
            preimage.extend_from_slice(&identity.ed25519_verifying_key);
            match store.sign_authentication_transcript(preimage) {
                Err(AetherError::InvalidData { .. }) => {}
                Err(error) => panic!("expected InvalidData for {context}, got {error}"),
                Ok(_) => panic!("expected InvalidData for {context}"),
            }
        }
    }

    #[test]
    fn sign_authentication_transcript_bounds_transcript_length() {
        let store = key_store();
        store.generate_identity().unwrap();

        match store.sign_authentication_transcript(Vec::new()) {
            Err(AetherError::InvalidData { .. }) => {}
            other => panic!("expected InvalidData for an empty transcript, got {other:?}"),
        }
        match store
            .sign_authentication_transcript(vec![0x41; MAX_AUTHENTICATION_TRANSCRIPT_LEN + 1])
        {
            Err(AetherError::InvalidData { .. }) => {}
            other => panic!("expected InvalidData past the length cap, got {other:?}"),
        }
        assert!(
            store
                .sign_authentication_transcript(vec![0x41; MAX_AUTHENTICATION_TRANSCRIPT_LEN])
                .is_ok()
        );
    }

    #[test]
    fn sign_authentication_transcript_requires_a_stored_identity() {
        let store = key_store();

        match store.sign_authentication_transcript(b"Relay-HTTP-Auth-v1".to_vec()) {
            Err(AetherError::NotFound) => {}
            other => panic!("expected NotFound without an identity, got {other:?}"),
        }
    }

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

    fn assert_discovery_to_identity_verifies(
        identity: &FfiIdentity,
        publication: &FfiPublicationBundle,
        discovery: &CryptoDiscoveryKeyBundle,
    ) {
        let signature = Signature::from_bytes(
            &<[u8; 64]>::try_from(publication.discovery_to_identity.as_slice()).unwrap(),
        );
        assert!(
            verify_discovery_to_identity_binding(
                &identity_bundle(identity),
                &discovery.verifying_key,
                &signature,
            )
            .is_ok()
        );
    }

    fn assert_publication_verifies(identity: &FfiIdentity, publication: &FfiPublicationBundle) {
        assert_eq!(publication.version, aether_crypto::PREKEY_BUNDLE_VERSION);
        let discovery = assert_discovery_key_verifies(identity, &publication.discovery_key);
        assert_signed_prekey_verifies(&publication.signed_prekey, &discovery);
        assert_discovery_to_identity_verifies(identity, publication, &discovery);
    }

    /// The host registers the verifier and shares the capability only with authorized contacts, so
    /// both must cross the FFI boundary and the verifier must commit to the capability actually in
    /// storage (AE-IDN-10).
    #[test]
    fn publication_verifier_commits_to_the_capability_across_ffi() {
        let key_store = key_store();
        key_store.generate_identity().unwrap();
        key_store.rotate_signed_prekey_now().unwrap();

        let publication = key_store.current_publication_bundle().unwrap();
        let capability = key_store.current_delivery_capability().unwrap();

        assert_eq!(publication.recipient_delivery_verifier.len(), 32);
        assert_eq!(capability.len(), 32);
        // The capability is the secret; publishing it instead of the verifier would be the whole
        // bug this separation exists to prevent.
        assert_ne!(publication.recipient_delivery_verifier, capability);

        let expected =
            CryptoCapability::from_bytes(<[u8; 32]>::try_from(capability.as_slice()).unwrap());
        assert_eq!(
            publication.recipient_delivery_verifier,
            expected.verifier().as_bytes().to_vec()
        );
    }

    /// The DK→IK binding must survive the FFI boundary as 64 usable bytes, not merely exist on the
    /// Rust side. A host reads this field straight out of the generated record to populate
    /// `relay.cloud.v1.KeyBindingSignatures.discovery_to_identity`.
    #[test]
    fn publication_bundle_carries_discovery_to_identity_binding_across_ffi() {
        let key_store = key_store();
        let identity = key_store.generate_identity().unwrap();
        key_store.rotate_signed_prekey_now().unwrap();

        let publication = key_store.current_publication_bundle().unwrap();

        assert_eq!(publication.discovery_to_identity.len(), 64);
        assert_ne!(publication.discovery_to_identity, vec![0u8; 64]);
        assert_publication_verifies(&identity, &publication);
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
            ) | (
                ProtocolStateKind::DeduplicationSet,
                ProtocolStateKind::DeduplicationSet
            ) | (
                ProtocolStateKind::PendingAcknowledgments,
                ProtocolStateKind::PendingAcknowledgments
            ) | (
                ProtocolStateKind::ContactState,
                ProtocolStateKind::ContactState
            ) | (
                ProtocolStateKind::PeerInboxAuthorization,
                ProtocolStateKind::PeerInboxAuthorization
            ) | (
                ProtocolStateKind::LocalInboxAuthorization,
                ProtocolStateKind::LocalInboxAuthorization
            )
        )
    }

    fn assert_protocol_state_kind(actual: ProtocolStateKind, expected: ProtocolStateKind) {
        assert!(same_protocol_state_kind(actual, expected));
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

    #[test]
    fn wipe_returns_only_active_protocol_state_kinds() {
        let engine = ProtocolStateEngine::new();

        let updates = engine.wipe(vec![0x44; 16]).unwrap();

        assert_eq!(updates.len(), 6);
        assert_protocol_state_kind(updates[0].kind, ProtocolStateKind::RatchetSession);
        assert_protocol_state_kind(updates[1].kind, ProtocolStateKind::DeduplicationSet);
        assert_protocol_state_kind(updates[2].kind, ProtocolStateKind::PendingAcknowledgments);
        assert_protocol_state_kind(updates[3].kind, ProtocolStateKind::ContactState);
        // A wipe must reach the peer's delivery capability too, or session replacement leaves a
        // stale bearer secret behind with nothing left that uses it.
        assert_protocol_state_kind(updates[4].kind, ProtocolStateKind::PeerInboxAuthorization);
        assert_protocol_state_kind(updates[5].kind, ProtocolStateKind::LocalInboxAuthorization);
        assert!(updates.iter().all(|update| update.blob.is_none()));
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
    fn rotate_inbox_now_advances_epoch_and_returns_verifiable_records() {
        let store = key_store();
        let identity = store.generate_identity().unwrap();
        let initial_discovery = store.current_discovery_key_bundle().unwrap();
        let rotation = store.rotate_inbox_now().unwrap();
        assert_eq!(
            rotation.publication.discovery_key.epoch,
            initial_discovery.epoch + 1
        );
        assert_publication_verifies(&identity, &rotation.publication);
        // The capability returned by the rotation is the one the new verifier commits to.
        assert_eq!(rotation.capability.len(), 32);
        assert_eq!(
            rotation.capability,
            store.current_delivery_capability().unwrap()
        );
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
            .accept_session(session_key, Some(alice_identity), initiation.message)
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
                Some(alice_identity),
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
                Some(alice_identity.clone()),
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
