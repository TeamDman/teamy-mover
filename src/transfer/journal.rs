//! Bounded, checksummed transfer-journal records and transition validation.
//!
//! This is not the complete operational journal: it does not yet record
//! individual staged-file identities or receipts. It performs no filesystem
//! I/O and does not establish ownership, stage isolation, persistence or crash
//! durability. A checksum detects corruption; it does not authenticate an
//! attacker-controlled record.

use crate::transfer::manifest::parse_approved_manifest;
use crate::transfer::manifest::valid_component;
use eyre::Result;
use eyre::bail;
use eyre::ensure;
use facet::Facet;
use sha2::Digest;
use sha2::Sha256;
use std::fmt;

const MAGIC: &[u8; 4] = b"TMJ1";
const HEADER_BYTES: usize = 8;
const CHECKSUM_BYTES: usize = 32;
const MAX_RECORD_BYTES: usize = 256 * 1024;
const MAX_JOURNAL_BYTES: usize = 1024 * 1024;

/// Filesystem object identity provisioned from verified local handles.
#[derive(Clone, Copy, Debug, Facet, PartialEq, Eq)]
#[facet(deny_unknown_fields)]
pub struct ObjectIdentity {
    pub volume_serial: u32,
    pub file_index: u64,
}

/// Local approval inputs. These values must not come from an untrusted peer.
pub struct JournalApproval<'a> {
    pub manifest_bytes: &'a [u8],
    pub manifest_sha256: &'a str,
    pub transaction_id: &'a str,
    pub client_pin: &'a str,
    pub server_pin: &'a str,
    pub destination_parent: ObjectIdentity,
    pub stage_directory: ObjectIdentity,
    pub journal_file: ObjectIdentity,
    pub final_name: &'a str,
    pub now_unix: u64,
}

impl fmt::Debug for JournalApproval<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JournalApproval").finish_non_exhaustive()
    }
}

#[derive(Clone, Facet, PartialEq, Eq)]
#[facet(deny_unknown_fields)]
struct Binding {
    client_pin: String,
    destination_parent: ObjectIdentity,
    expires_unix: u64,
    final_name: String,
    journal_file: ObjectIdentity,
    manifest: String,
    manifest_sha256: String,
    server_pin: String,
    stage_directory: ObjectIdentity,
    transaction_id: String,
}

/// A journal binding checked against local approval data.
#[derive(Clone, Facet, PartialEq, Eq)]
#[facet(transparent)]
pub struct JournalBinding(Binding);

impl fmt::Debug for JournalBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JournalBinding").finish_non_exhaustive()
    }
}

fn pin_is_valid(pin: &str) -> bool {
    pin.len() == 64
        && pin
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl JournalBinding {
    #[cfg(windows)]
    pub(crate) fn matches_publication_target(&self, parent: ObjectIdentity, name: &str) -> bool {
        self.0.destination_parent == parent && self.0.final_name == name
    }

    #[cfg(windows)]
    pub(crate) fn matches_client_pin(&self, pin: &[u8; 32]) -> bool {
        self.0.client_pin == Self::format_pin(pin)
    }

    #[cfg(windows)]
    pub(crate) fn matches_server_pin(&self, pin: &[u8; 32]) -> bool {
        self.0.server_pin == Self::format_pin(pin)
    }

    #[cfg(windows)]
    fn format_pin(pin: &[u8; 32]) -> String {
        use std::fmt::Write as _;
        let mut hex = String::with_capacity(64);
        for byte in pin {
            let _ignored = write!(&mut hex, "{byte:02x}");
        }
        hex
    }

    /// Bind a canonical approved manifest to peer pins and filesystem IDs.
    /// A real receiver must independently establish trusted handles and ACLs.
    ///
    /// # Errors
    /// Returns an error when any approval input is invalid or expired.
    pub fn from_approval(approval: &JournalApproval<'_>) -> Result<Self> {
        let manifest = parse_approved_manifest(
            approval.manifest_bytes,
            approval.manifest_sha256,
            approval.transaction_id,
            approval.now_unix,
        )?;
        ensure!(pin_is_valid(approval.client_pin), "invalid client pin");
        ensure!(pin_is_valid(approval.server_pin), "invalid server pin");
        ensure!(
            valid_component(approval.final_name),
            "invalid final directory name"
        );
        ensure!(
            approval.destination_parent.file_index != 0
                && approval.stage_directory.file_index != 0
                && approval.journal_file.file_index != 0,
            "invalid filesystem identity"
        );
        ensure!(
            approval.destination_parent.volume_serial == approval.stage_directory.volume_serial
                && approval.destination_parent != approval.stage_directory,
            "stage and parent must be distinct identities on one volume"
        );
        ensure!(
            approval.journal_file != approval.destination_parent
                && approval.journal_file != approval.stage_directory,
            "journal file must have a distinct identity"
        );
        let manifest_text = std::str::from_utf8(approval.manifest_bytes)?.to_owned();
        Ok(Self(Binding {
            client_pin: approval.client_pin.to_owned(),
            destination_parent: approval.destination_parent,
            expires_unix: manifest.expires_unix(),
            final_name: approval.final_name.to_owned(),
            journal_file: approval.journal_file,
            manifest: manifest_text,
            manifest_sha256: approval.manifest_sha256.to_owned(),
            server_pin: approval.server_pin.to_owned(),
            stage_directory: approval.stage_directory,
            transaction_id: approval.transaction_id.to_owned(),
        }))
    }
}

/// Coarse journal phase. It is not evidence that a filesystem operation occurred.
#[derive(Clone, Copy, Debug, Facet, PartialEq, Eq)]
#[facet(rename_all = "kebab-case")]
#[repr(u8)]
pub enum JournalPhase {
    Approved,
    Receiving,
    Verified,
    CommitIntent,
    Published,
    ReceiptRecorded,
    Aborted,
}

#[derive(Clone, Facet, PartialEq, Eq)]
#[facet(deny_unknown_fields)]
struct Record {
    binding: JournalBinding,
    phase: JournalPhase,
    sequence: u64,
    version: u32,
}

/// An immutable phase record. The receiver must prove each transition's
/// filesystem preconditions before persisting it.
#[derive(Clone, Facet, PartialEq, Eq)]
#[facet(transparent)]
pub struct JournalRecord(Record);

impl fmt::Debug for JournalRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JournalRecord")
            .field("phase", &self.0.phase)
            .field("sequence", &self.0.sequence)
            .finish_non_exhaustive()
    }
}

fn valid_transition(old: JournalPhase, next: JournalPhase) -> bool {
    use JournalPhase as P;
    matches!(
        (old, next),
        (P::Approved, P::Receiving | P::Aborted)
            | (P::Receiving, P::Receiving | P::Verified | P::Aborted)
            | (P::Verified, P::CommitIntent | P::Aborted)
            | (P::CommitIntent, P::Published)
            | (P::Published, P::ReceiptRecorded)
    )
}

impl JournalRecord {
    #[must_use]
    pub fn initial(binding: &JournalBinding) -> Self {
        Self(Record {
            binding: binding.clone(),
            phase: JournalPhase::Approved,
            sequence: 1,
            version: 1,
        })
    }

    #[must_use]
    pub const fn phase(&self) -> JournalPhase {
        self.0.phase
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.0.sequence
    }

    /// Construct the next syntactically valid state; this does not verify its
    /// filesystem preconditions or write it to persistent storage.
    ///
    /// # Errors
    /// Returns an error for an invalid transition or exhausted sequence.
    pub fn next(&self, phase: JournalPhase) -> Result<Self> {
        ensure!(
            valid_transition(self.0.phase, phase),
            "invalid journal transition"
        );
        let sequence = self
            .0
            .sequence
            .checked_add(1)
            .ok_or_else(|| eyre::eyre!("journal sequence exhausted"))?;
        Ok(Self(Record {
            binding: self.0.binding.clone(),
            phase,
            sequence,
            version: 1,
        }))
    }
}

/// Encode a checksummed frame for a record. Callers must enforce exclusive
/// ownership, validate the predecessor, write in order and sync independently.
///
/// # Errors
/// Returns an error if the record cannot be serialized within the size limit.
pub fn encode_frame(record: &JournalRecord) -> Result<Vec<u8>> {
    let payload = facet_json::to_string(record)?;
    ensure!(
        payload.len() <= MAX_RECORD_BYTES,
        "journal record exceeds limit"
    );
    let len = u32::try_from(payload.len())?;
    let mut frame = Vec::with_capacity(HEADER_BYTES + payload.len() + CHECKSUM_BYTES);
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(payload.as_bytes());
    let checksum = Sha256::digest(&frame);
    frame.extend_from_slice(&checksum);
    Ok(frame)
}

/// Decode an entire journal and bind every record to the local approval.
/// Incomplete, reordered, corrupted, conflicting or expired logs fail closed.
/// This routine does not authenticate file ownership or repair a torn write.
///
/// # Errors
/// Returns an error when any record or transition is invalid.
pub fn decode_log(
    bytes: &[u8],
    approved: &JournalBinding,
    now_unix: u64,
) -> Result<Vec<JournalRecord>> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_JOURNAL_BYTES,
        "invalid journal size"
    );
    ensure!(
        approved.0.expires_unix > now_unix,
        "journal authorization has expired"
    );
    let mut offset = 0_usize;
    let mut records: Vec<JournalRecord> = Vec::new();
    while offset < bytes.len() {
        let remaining = &bytes[offset..];
        ensure!(
            remaining.len() >= HEADER_BYTES + CHECKSUM_BYTES,
            "truncated journal frame"
        );
        ensure!(&remaining[..4] == MAGIC, "unknown journal frame version");
        let payload_len = u32::from_be_bytes(remaining[4..8].try_into()?) as usize;
        ensure!(
            payload_len <= MAX_RECORD_BYTES,
            "journal record exceeds limit"
        );
        let body_end = HEADER_BYTES
            .checked_add(payload_len)
            .ok_or_else(|| eyre::eyre!("journal size overflow"))?;
        let frame_end = body_end
            .checked_add(CHECKSUM_BYTES)
            .ok_or_else(|| eyre::eyre!("journal size overflow"))?;
        ensure!(frame_end <= remaining.len(), "truncated journal frame");
        let expected = Sha256::digest(&remaining[..body_end]);
        ensure!(
            expected[..] == remaining[body_end..frame_end],
            "journal checksum mismatch"
        );
        let payload = &remaining[HEADER_BYTES..body_end];
        let record: JournalRecord = facet_json::from_slice(payload)
            .map_err(|_error| eyre::eyre!("invalid journal record"))?;
        ensure!(
            facet_json::to_string(&record)?.as_bytes() == payload,
            "noncanonical journal record"
        );
        ensure!(
            record.0.version == 1 && &record.0.binding == approved,
            "journal binding mismatch"
        );
        if let Some(previous) = records.last() {
            ensure!(
                previous.next(record.0.phase)? == record,
                "journal sequence mismatch"
            );
        } else if record != JournalRecord::initial(approved) {
            bail!("journal must begin with the approved state");
        }
        records.push(record);
        offset = offset
            .checked_add(frame_end)
            .ok_or_else(|| eyre::eyre!("journal size overflow"))?;
    }
    Ok(records)
}
