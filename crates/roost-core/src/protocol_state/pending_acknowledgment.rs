use super::grant::DiscoveryKeyStamp;
use super::session::{pending_acknowledgment_address, session_record_addresses};
use super::{
    DIGEST_LEN, PROTOCOL_STATE_BLOB_HEADER_LEN, ProtocolStateAddress, ProtocolStateBlob,
    ProtocolStateEngine, ProtocolStateError, ProtocolStateSnapshot, ProtocolStateUpdate, blob_body,
    contains_digest, deserialize_bounded, digest_of, encode_blob, push_bounded,
};
use crate::hardening::{
    MAX_ACKNOWLEDGMENT_DIGESTS, MAX_PENDING_ACKNOWLEDGMENTS, ProtocolHardeningLimits,
};
use roost_crypto::SealedFrame;
use roost_protocol::{MessageId, PayloadKind, SessionId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

const ACKNOWLEDGMENT_DIGEST_LABEL: &[u8] = b"RoostAcknowledgmentDigest-v1:";
const PENDING_ACKNOWLEDGMENT_ENTRY_OVERHEAD_CAP: usize = 64;
const PENDING_ACKNOWLEDGMENTS_WIRE_OVERHEAD_CAP: usize = 64;

/// Pending acknowledgment state exposed to the consumer for durable flushing.
pub struct PendingAcknowledgment {
    /// Original outbound Message ID.
    pub message_id: MessageId,
    /// Original outbound Message waiting for an acknowledgment.
    pub message: SealedFrame,
    /// First-send Unix timestamp in milliseconds.
    pub first_sent_at_millis: u64,
}

impl ProtocolStateEngine {
    /// Returns all pending acknowledgments stored for a Session.
    pub fn pending_acknowledgments(
        &self,
        snapshot: &ProtocolStateSnapshot,
        session_id: SessionId,
    ) -> Result<Vec<PendingAcknowledgment>, ProtocolStateError> {
        let address = pending_acknowledgment_address(session_id);
        let pending = load_pending_acknowledgments(snapshot, &address, self.limits)?;
        Ok(pending
            .pending
            .iter()
            .map(|(message_id, entry)| PendingAcknowledgment {
                message_id: MessageId::from_bytes(*message_id),
                message: entry.message.clone(),
                first_sent_at_millis: entry.first_sent_at_millis,
            })
            .collect())
    }
}

pub(super) struct LoadedPendingAcknowledgments {
    pub(super) pending: BTreeMap<[u8; 16], LoadedPendingAcknowledgment>,
    acknowledgment_digests: Vec<[u8; DIGEST_LEN]>,
}

impl LoadedPendingAcknowledgments {
    // A new Session's list, with nothing waiting and no acknowledgment seen.
    pub(super) fn empty() -> Self {
        Self {
            pending: BTreeMap::new(),
            acknowledgment_digests: Vec::new(),
        }
    }

    // Records a Message waiting for its acknowledgment, refusing one past the limit.
    pub(super) fn record(
        &mut self,
        message_id: MessageId,
        entry: LoadedPendingAcknowledgment,
    ) -> Result<(), ProtocolStateError> {
        let message_id = *message_id.as_bytes();
        if !self.pending.contains_key(&message_id)
            && self.pending.len() == MAX_PENDING_ACKNOWLEDGMENTS
        {
            return Err(ProtocolStateError::PendingAcknowledgmentLimitReached {
                limit: MAX_PENDING_ACKNOWLEDGMENTS,
            });
        }
        self.pending.insert(message_id, entry);
        Ok(())
    }

    // Records an acknowledgment's digest, so a repeat of its bytes is a duplicate, forgetting the
    // oldest past the limit.
    pub(super) fn record_acknowledgment(&mut self, digest: [u8; DIGEST_LEN]) {
        push_bounded(
            &mut self.acknowledgment_digests,
            digest,
            MAX_ACKNOWLEDGMENT_DIGESTS,
        );
    }
}

pub(super) struct LoadedPendingAcknowledgment {
    pub(super) message: SealedFrame,
    encoded_message: Vec<u8>,
    pub(super) first_sent_at_millis: u64,
    /// The payload kind sealed in the Message, which a recovery keeps when it resends it.
    pub(super) payload_kind: PayloadKind,
    /// The local grant the Message carried, which its acknowledgment confirms the peer holds.
    pub(super) grant: Option<DiscoveryKeyStamp>,
}

impl LoadedPendingAcknowledgment {
    pub(super) fn new(
        message: &SealedFrame,
        first_sent_at_millis: u64,
        payload_kind: PayloadKind,
        grant: Option<DiscoveryKeyStamp>,
    ) -> Result<Self, ProtocolStateError> {
        Ok(Self {
            message: message.clone(),
            encoded_message: message.to_bytes()?,
            first_sent_at_millis,
            payload_kind,
            grant,
        })
    }
}

// Borrows each Message's bytes, so checking for a repeated acknowledgment parses no Message.
#[derive(Deserialize, Serialize)]
struct PendingAcknowledgmentsWire<'a> {
    #[serde(
        borrow,
        deserialize_with = "deserialize_bounded::<_, _, MAX_PENDING_ACKNOWLEDGMENTS>"
    )]
    pending: Vec<PendingAcknowledgmentWire<'a>>,
    #[serde(deserialize_with = "deserialize_bounded::<_, _, MAX_ACKNOWLEDGMENT_DIGESTS>")]
    acknowledgment_digests: Vec<[u8; DIGEST_LEN]>,
}

#[derive(Deserialize, Serialize)]
struct PendingAcknowledgmentWire<'a> {
    message_id: [u8; 16],
    encoded_message: &'a [u8],
    first_sent_at_millis: u64,
    payload_kind: u8,
    grant: Option<(u64, u32)>,
}

pub(super) fn encode_pending_acknowledgments(
    address: &ProtocolStateAddress,
    state: &LoadedPendingAcknowledgments,
    limits: ProtocolHardeningLimits,
) -> Result<ProtocolStateBlob, ProtocolStateError> {
    let pending = state
        .pending
        .iter()
        .map(|(message_id, entry)| PendingAcknowledgmentWire {
            message_id: *message_id,
            encoded_message: &entry.encoded_message,
            first_sent_at_millis: entry.first_sent_at_millis,
            payload_kind: entry.payload_kind.tag(),
            grant: entry.grant.map(DiscoveryKeyStamp::to_wire),
        })
        .collect();
    let body = Zeroizing::new(
        postcard::to_stdvec(&PendingAcknowledgmentsWire {
            pending,
            acknowledgment_digests: state.acknowledgment_digests.clone(),
        })
        .map_err(|_| ProtocolStateError::BlobEncode {
            address: address.clone(),
            reason: "pending acknowledgments failed to encode".into(),
        })?,
    );
    encode_blob(address, &body, max_pending_acknowledgments_blob_len(limits))
}

pub(super) fn load_pending_acknowledgments(
    snapshot: &ProtocolStateSnapshot,
    address: &ProtocolStateAddress,
    limits: ProtocolHardeningLimits,
) -> Result<LoadedPendingAcknowledgments, ProtocolStateError> {
    let blob = snapshot
        .get(address)
        .ok_or_else(|| ProtocolStateError::MissingRequiredState {
            address: address.clone(),
        })?;
    decode_pending_acknowledgments(address, blob, limits)
}

// Returns whether the Session at `address` already processed an acknowledgment with `digest`.
pub(super) fn has_seen_acknowledgment(
    snapshot: &ProtocolStateSnapshot,
    address: &ProtocolStateAddress,
    digest: [u8; DIGEST_LEN],
    limits: ProtocolHardeningLimits,
) -> Result<bool, ProtocolStateError> {
    let blob = snapshot
        .get(address)
        .ok_or_else(|| ProtocolStateError::MissingRequiredState {
            address: address.clone(),
        })?;
    let wire = decode_wire(address, blob, limits)?;
    Ok(contains_digest(&wire.acknowledgment_digests, &digest))
}

pub(super) fn decode_pending_acknowledgments(
    address: &ProtocolStateAddress,
    blob: &ProtocolStateBlob,
    limits: ProtocolHardeningLimits,
) -> Result<LoadedPendingAcknowledgments, ProtocolStateError> {
    let wire = decode_wire(address, blob, limits)?;
    let mut pending = BTreeMap::new();
    for entry in wire.pending {
        let message = SealedFrame::from_bytes(entry.encoded_message).map_err(|e| {
            decode_error(
                address,
                format!("pending acknowledgment message failed to decode: {e}"),
            )
        })?;
        let payload_kind = PayloadKind::from_tag(entry.payload_kind)
            .ok_or_else(|| decode_error(address, "pending payload kind is invalid".into()))?;
        let replaced = pending.insert(
            entry.message_id,
            LoadedPendingAcknowledgment {
                message,
                encoded_message: entry.encoded_message.to_vec(),
                first_sent_at_millis: entry.first_sent_at_millis,
                payload_kind,
                grant: entry.grant.map(DiscoveryKeyStamp::from_wire),
            },
        );
        if replaced.is_some() {
            return Err(decode_error(
                address,
                "pending acknowledgment message ID is duplicated".into(),
            ));
        }
    }
    Ok(LoadedPendingAcknowledgments {
        pending,
        acknowledgment_digests: wire.acknowledgment_digests,
    })
}

fn decode_wire<'a>(
    address: &ProtocolStateAddress,
    blob: &'a ProtocolStateBlob,
    limits: ProtocolHardeningLimits,
) -> Result<PendingAcknowledgmentsWire<'a>, ProtocolStateError> {
    let body = blob_body(address, blob, max_pending_acknowledgments_blob_len(limits))?;
    let (wire, trailing): (PendingAcknowledgmentsWire<'_>, &[u8]) =
        postcard::take_from_bytes(body).map_err(|e| decode_error(address, e.to_string()))?;
    if !trailing.is_empty() {
        return Err(decode_error(
            address,
            "pending acknowledgments have trailing bytes".into(),
        ));
    }
    Ok(wire)
}

fn decode_error(address: &ProtocolStateAddress, reason: String) -> ProtocolStateError {
    ProtocolStateError::BlobDecode {
        address: address.clone(),
        reason,
    }
}

fn max_pending_acknowledgments_blob_len(limits: ProtocolHardeningLimits) -> usize {
    PROTOCOL_STATE_BLOB_HEADER_LEN
        + PENDING_ACKNOWLEDGMENTS_WIRE_OVERHEAD_CAP
        + limits.max_pending_acknowledgments
            * (limits.max_encoded_message_len + PENDING_ACKNOWLEDGMENT_ENTRY_OVERHEAD_CAP)
        + limits.max_acknowledgment_digests * DIGEST_LEN
}

// Returns the deletions of each evicted Session's records, which the operation must have read,
// and the Messages still waiting on those Sessions, oldest first, which no acknowledgment can
// reach once the Sessions are gone.
pub(super) fn evict_sessions(
    snapshot: &ProtocolStateSnapshot,
    evicted: &[SessionId],
    limits: ProtocolHardeningLimits,
) -> Result<(Vec<ProtocolStateUpdate>, Vec<MessageId>), ProtocolStateError> {
    let mut stranded = Vec::new();
    for session_id in evicted {
        let address = pending_acknowledgment_address(*session_id);
        if let Some(blob) = snapshot.get(&address) {
            let pending = decode_pending_acknowledgments(&address, blob, limits)?;
            stranded.extend(
                pending
                    .pending
                    .iter()
                    .map(|(message_id, entry)| (entry.first_sent_at_millis, *message_id)),
            );
        }
    }
    stranded.sort_unstable();
    let deletions = evicted
        .iter()
        .flat_map(|session_id| session_record_addresses(*session_id))
        .map(|address| ProtocolStateUpdate::delete(address).with_snapshot(snapshot))
        .collect();
    let undelivered = stranded
        .into_iter()
        .map(|(_, message_id)| MessageId::from_bytes(message_id))
        .collect();
    Ok((deletions, undelivered))
}

// Returns the digest that catches a repeated delivery of one acknowledgment's bytes.
pub(super) fn acknowledgment_digest(
    transport_binding: &[u8],
    encoded_message: &[u8],
) -> [u8; DIGEST_LEN] {
    digest_of(
        blake3::Hasher::new(),
        ACKNOWLEDGMENT_DIGEST_LABEL,
        transport_binding,
        encoded_message,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acknowledgment_digest_changes_with_each_input() {
        let expected = acknowledgment_digest(b"transport-binding", b"encoded message");

        assert_ne!(
            acknowledgment_digest(b"other-binding", b"encoded message"),
            expected
        );
        assert_ne!(
            acknowledgment_digest(b"transport-binding", b"other message"),
            expected
        );
    }

    fn address() -> ProtocolStateAddress {
        pending_acknowledgment_address(SessionId::from_bytes([9; 16]))
    }

    #[test]
    fn a_repeated_acknowledgment_is_found_without_decoding_any_waiting_message() {
        let address = address();
        let limits = ProtocolHardeningLimits::default();
        let digest = acknowledgment_digest(b"transport-binding", b"encoded acknowledgment");
        let body = postcard::to_stdvec(&PendingAcknowledgmentsWire {
            pending: vec![PendingAcknowledgmentWire {
                message_id: [0x44; 16],
                encoded_message: &[0xaa],
                first_sent_at_millis: 1_700_000_100_123,
                payload_kind: 0,
                grant: None,
            }],
            acknowledgment_digests: vec![digest],
        })
        .unwrap();
        let mut snapshot = ProtocolStateSnapshot::new();
        snapshot
            .set(
                address.clone(),
                encode_blob(&address, &body, usize::MAX).unwrap(),
            )
            .unwrap();

        assert!(has_seen_acknowledgment(&snapshot, &address, digest, limits).unwrap());
        assert!(matches!(
            load_pending_acknowledgments(&snapshot, &address, limits),
            Err(ProtocolStateError::BlobDecode { .. })
        ));
    }

    #[test]
    fn pending_acknowledgments_of_another_version_are_unsupported() {
        let address = address();
        let limits = ProtocolHardeningLimits::default();
        let mut bytes = encode_pending_acknowledgments(
            &address,
            &LoadedPendingAcknowledgments::empty(),
            limits,
        )
        .unwrap()
        .as_bytes()
        .to_vec();
        bytes[0] += 1;

        assert!(matches!(
            decode_pending_acknowledgments(&address, &ProtocolStateBlob::from_bytes(bytes), limits),
            Err(ProtocolStateError::UnsupportedBlobVersion { address: actual, version })
                if actual == address && version == super::super::PROTOCOL_STATE_BLOB_VERSION + 1
        ));
    }
}
