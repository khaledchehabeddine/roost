use super::grant::DiscoveryKeyStamp;
use super::session::{pending_acknowledgment_address, session_record_addresses};
use super::{
    DIGEST_LEN, PROTOCOL_STATE_BLOB_HEADER_LEN, ProtocolStateAddress, ProtocolStateBlob,
    ProtocolStateEngine, ProtocolStateError, ProtocolStateSnapshot, ProtocolStateUpdate,
    contains_digest, decode_blob, decode_error, deserialize_bounded, digest_of, encode_blob,
    push_bounded,
};
use crate::hardening::{
    MAX_ACKNOWLEDGMENT_DIGESTS, MAX_PENDING_ACKNOWLEDGMENTS, ProtocolHardeningLimits,
};
use roost_protocol::{MessageId, PayloadKind, SessionId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const ACKNOWLEDGMENT_DIGEST_LABEL: &[u8] = b"RoostAcknowledgmentDigest-v1:";
const PENDING_ACKNOWLEDGMENT_ENTRY_CAP: usize = 64;
const PENDING_ACKNOWLEDGMENTS_WIRE_OVERHEAD_CAP: usize = 64;

/// A sent message still waiting for its acknowledgment.
///
/// Roost keeps no copy of the message, so a recovery encrypts the app's copy of its content again.
pub struct PendingAcknowledgment {
    /// The message ID.
    pub message_id: MessageId,
    /// First-send Unix timestamp in milliseconds.
    pub first_sent_at_millis: u64,
}

impl ProtocolStateEngine {
    /// Returns the messages waiting for an acknowledgment on `session_id`, given its pending
    /// acknowledgment record or the record's absence.
    pub fn pending_acknowledgments(
        &self,
        session_id: SessionId,
        record: Option<&ProtocolStateBlob>,
    ) -> Result<Vec<PendingAcknowledgment>, ProtocolStateError> {
        let Some(blob) = record else {
            return Ok(Vec::new());
        };
        let address = pending_acknowledgment_address(session_id);
        let pending = decode_pending_acknowledgments(&address, blob, self.limits)?;
        Ok(pending
            .pending
            .iter()
            .map(|(message_id, entry)| PendingAcknowledgment {
                message_id: MessageId::from_bytes(*message_id),
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
    pub(super) fn empty() -> Self {
        Self {
            pending: BTreeMap::new(),
            acknowledgment_digests: Vec::new(),
        }
    }

    // Records a message waiting for its acknowledgment, refusing one past the limit.
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
    pub(super) first_sent_at_millis: u64,
    /// The payload kind sealed in the message. A recovery skips grant updates, keeps a contact
    /// acceptance when it resends on a session the peer started, and picks the content kind again
    /// for the rest.
    pub(super) payload_kind: PayloadKind,
    /// The local grant the message carried, which its acknowledgment confirms the peer holds.
    pub(super) grant: Option<DiscoveryKeyStamp>,
    /// The peer's discovery key the message went to, whose inbox a newer grant shows may be gone.
    pub(super) sent_to: Option<DiscoveryKeyStamp>,
    /// Whether the message waits here behind a recovery's probe with no copy on this session yet,
    /// since the probe's new session deleted the one it went out on.
    pub(super) held: bool,
}

#[derive(Serialize)]
struct PendingAcknowledgmentsWire<'a> {
    pending: Vec<PendingAcknowledgmentWire>,
    acknowledgment_digests: &'a [[u8; DIGEST_LEN]],
}

#[derive(Deserialize)]
struct DecodedPendingAcknowledgmentsWire {
    #[serde(deserialize_with = "deserialize_bounded::<_, _, MAX_PENDING_ACKNOWLEDGMENTS>")]
    pending: Vec<PendingAcknowledgmentWire>,
    #[serde(deserialize_with = "deserialize_bounded::<_, _, MAX_ACKNOWLEDGMENT_DIGESTS>")]
    acknowledgment_digests: Vec<[u8; DIGEST_LEN]>,
}

#[derive(Deserialize, Serialize)]
struct PendingAcknowledgmentWire {
    message_id: [u8; 16],
    first_sent_at_millis: u64,
    payload_kind: u8,
    grant: Option<(u64, u32)>,
    sent_to: Option<(u64, u32)>,
    held: bool,
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
            first_sent_at_millis: entry.first_sent_at_millis,
            payload_kind: entry.payload_kind.tag(),
            grant: entry.grant.map(DiscoveryKeyStamp::to_wire),
            sent_to: entry.sent_to.map(DiscoveryKeyStamp::to_wire),
            held: entry.held,
        })
        .collect();
    let body = postcard::to_stdvec(&PendingAcknowledgmentsWire {
        pending,
        acknowledgment_digests: &state.acknowledgment_digests,
    })
    .map_err(|_| ProtocolStateError::BlobEncode {
        address: address.clone(),
        reason: "pending acknowledgments failed to encode".into(),
    })?;
    encode_blob(address, &body, max_pending_acknowledgments_blob_len(limits))
}

// Returns the session's pending acknowledgments. A session that lost this record keeps working,
// since its keys are intact, with nothing waiting on it.
pub(super) fn load_pending_acknowledgments(
    snapshot: &ProtocolStateSnapshot,
    address: &ProtocolStateAddress,
    limits: ProtocolHardeningLimits,
) -> Result<LoadedPendingAcknowledgments, ProtocolStateError> {
    match snapshot.get(address) {
        Some(blob) => decode_pending_acknowledgments(address, blob, limits),
        None => Ok(LoadedPendingAcknowledgments::empty()),
    }
}

pub(super) fn has_seen_acknowledgment(
    snapshot: &ProtocolStateSnapshot,
    address: &ProtocolStateAddress,
    digest: [u8; DIGEST_LEN],
    limits: ProtocolHardeningLimits,
) -> Result<bool, ProtocolStateError> {
    let Some(blob) = snapshot.get(address) else {
        return Ok(false);
    };
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
        let payload_kind = PayloadKind::from_tag(entry.payload_kind)
            .ok_or_else(|| decode_error(address, "pending payload kind is invalid"))?;
        let replaced = pending.insert(
            entry.message_id,
            LoadedPendingAcknowledgment {
                first_sent_at_millis: entry.first_sent_at_millis,
                payload_kind,
                grant: entry.grant.map(DiscoveryKeyStamp::from_wire),
                sent_to: entry.sent_to.map(DiscoveryKeyStamp::from_wire),
                held: entry.held,
            },
        );
        if replaced.is_some() {
            return Err(decode_error(
                address,
                "pending acknowledgment message ID is duplicated",
            ));
        }
    }
    Ok(LoadedPendingAcknowledgments {
        pending,
        acknowledgment_digests: wire.acknowledgment_digests,
    })
}

fn decode_wire(
    address: &ProtocolStateAddress,
    blob: &ProtocolStateBlob,
    limits: ProtocolHardeningLimits,
) -> Result<DecodedPendingAcknowledgmentsWire, ProtocolStateError> {
    decode_blob(address, blob, max_pending_acknowledgments_blob_len(limits))
}

fn max_pending_acknowledgments_blob_len(limits: ProtocolHardeningLimits) -> usize {
    PROTOCOL_STATE_BLOB_HEADER_LEN
        + PENDING_ACKNOWLEDGMENTS_WIRE_OVERHEAD_CAP
        + limits.max_pending_acknowledgments * PENDING_ACKNOWLEDGMENT_ENTRY_CAP
        + limits.max_acknowledgment_digests * DIGEST_LEN
}

// Returns the deletions of each evicted session's records, which the operation must have read,
// and the messages still waiting on those sessions, oldest first, which no acknowledgment can
// reach once the sessions are gone.
pub(super) fn evict_sessions(
    snapshot: &ProtocolStateSnapshot,
    evicted: &[SessionId],
    limits: ProtocolHardeningLimits,
) -> Result<(Vec<ProtocolStateUpdate>, Vec<StrandedMessage>), ProtocolStateError> {
    let mut stranded = Vec::new();
    for session_id in evicted {
        let address = pending_acknowledgment_address(*session_id);
        if let Some(blob) = snapshot.get(&address) {
            let pending = decode_pending_acknowledgments(&address, blob, limits)?;
            stranded.extend(pending.pending.into_iter().map(|(message_id, entry)| {
                StrandedMessage {
                    message_id: MessageId::from_bytes(message_id),
                    entry,
                }
            }));
        }
    }
    stranded.sort_unstable_by_key(|message| {
        (
            message.entry.first_sent_at_millis,
            *message.message_id.as_bytes(),
        )
    });
    let deletions = evicted
        .iter()
        .flat_map(|session_id| session_record_addresses(*session_id))
        .map(|address| ProtocolStateUpdate::delete(address).with_snapshot(snapshot))
        .collect();
    Ok((deletions, stranded))
}

// A message that waited on a session an operation evicts.
pub(super) struct StrandedMessage {
    pub(super) message_id: MessageId,
    pub(super) entry: LoadedPendingAcknowledgment,
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

    #[test]
    fn full_pending_acknowledgments_fit_their_blob_limit() {
        let address = address();
        let limits = ProtocolHardeningLimits::default();
        let mut state = LoadedPendingAcknowledgments::empty();
        for index in (0u128..).take(MAX_PENDING_ACKNOWLEDGMENTS) {
            // The largest values give each field its longest encoding.
            let entry = LoadedPendingAcknowledgment {
                first_sent_at_millis: u64::MAX,
                payload_kind: PayloadKind::ContentWithGrant,
                grant: Some(DiscoveryKeyStamp {
                    created_at_secs: u64::MAX,
                    epoch: u32::MAX,
                }),
                sent_to: Some(DiscoveryKeyStamp {
                    created_at_secs: u64::MAX,
                    epoch: u32::MAX,
                }),
                held: true,
            };
            state
                .record(MessageId::from_bytes(index.to_be_bytes()), entry)
                .unwrap();
        }
        for index in (0u128..).take(MAX_ACKNOWLEDGMENT_DIGESTS) {
            state.record_acknowledgment(index.to_be_bytes());
        }

        let blob = encode_pending_acknowledgments(&address, &state, limits).unwrap();
        let decoded = decode_pending_acknowledgments(&address, &blob, limits).unwrap();

        assert_eq!(decoded.pending.len(), MAX_PENDING_ACKNOWLEDGMENTS);
        assert_eq!(
            decoded.acknowledgment_digests.len(),
            MAX_ACKNOWLEDGMENT_DIGESTS
        );
    }

    #[test]
    fn pending_acknowledgments_longer_than_their_limit_are_rejected_before_decoding() {
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
        let left_over = 81_985 - bytes.len();
        bytes.resize(81_985, 0);
        let at_limit = ProtocolStateBlob::from_bytes(bytes.clone());
        bytes.push(0);
        let past_limit = ProtocolStateBlob::from_bytes(bytes);

        assert!(matches!(
            decode_pending_acknowledgments(&address, &at_limit, limits),
            Err(ProtocolStateError::BlobDecode { address: actual, reason })
                if actual == address
                    && reason == format!("pending-acknowledgment state has {left_over} bytes left over")
        ));
        assert!(matches!(
            decode_pending_acknowledgments(&address, &past_limit, limits),
            Err(ProtocolStateError::BlobDecode { address: actual, reason })
                if actual == address
                    && reason == "pending-acknowledgment state blob length 81986 exceeds limit 81985"
        ));
    }

    #[test]
    fn a_full_session_refuses_a_new_message_and_keeps_a_resend() {
        let entry = || LoadedPendingAcknowledgment {
            first_sent_at_millis: 1,
            payload_kind: PayloadKind::Content,
            grant: None,
            sent_to: None,
            held: false,
        };
        let mut state = LoadedPendingAcknowledgments::empty();
        for index in (0u128..).take(MAX_PENDING_ACKNOWLEDGMENTS) {
            state
                .record(MessageId::from_bytes(index.to_be_bytes()), entry())
                .unwrap();
        }

        assert!(matches!(
            state.record(MessageId::from_bytes(u128::MAX.to_be_bytes()), entry()),
            Err(ProtocolStateError::PendingAcknowledgmentLimitReached {
                limit: MAX_PENDING_ACKNOWLEDGMENTS
            })
        ));
        state
            .record(MessageId::from_bytes(0u128.to_be_bytes()), entry())
            .unwrap();
    }
}
