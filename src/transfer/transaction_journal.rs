//! Windows transaction journal for verified file observations.
//!
//! Records do not prove protected ancestry, safe staging, publication, or
//! power-loss durability. A commit-intent record is not permission to rename:
//! publication evidence and receipts do not establish safe staging or durability.

use super::blocking_io::BlockingIoGate;
use super::journal::JournalApproval;
use super::journal::JournalBinding;
use super::journal::ObjectIdentity;
use super::manifest::ApprovedManifest;
use super::manifest::parse_approved_manifest;
use super::manifest::parse_for_local_inspection;
use super::verified_stream::FileVerifier;
use super::windows_lock::ExclusiveFile;
use super::windows_lock::directory_identity;
use super::windows_lock::regular_file_identity;
use eyre::Result;
use eyre::bail;
use eyre::ensure;
use facet::Facet;
use sha2::Digest;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;

const MAX_LOG: usize = 1024 * 1024;
const MAX_FRAME: usize = 256 * 1024;
const MAGIC: &[u8; 4] = b"TMJ2";

#[derive(Clone, Debug, Facet, PartialEq, Eq)]
#[facet(deny_unknown_fields)]
struct FileObservation {
    id: String,
    object: ObjectIdentity,
    sha256: String,
    size: u64,
}

#[derive(Clone, Debug, Facet, PartialEq, Eq)]
#[facet(rename_all = "kebab-case")]
#[repr(u8)]
enum Event {
    Approved,
    FileClaimed(FileObservation),
    FileVerified(FileObservation),
    CommitIntent(ObjectIdentity),
    Aborted,
    Published(ObjectIdentity),
    ReceiptRecorded(String),
}

#[derive(Clone)]
struct FileEntry {
    observation: FileObservation,
    verified: bool,
}

#[derive(Clone, Default)]
struct Progress {
    aborted: bool,
    commit_intent: Option<ObjectIdentity>,
    published: Option<ObjectIdentity>,
    receipt: Option<String>,
}

#[derive(Facet)]
struct ReceiptFile<'a> {
    id: &'a str,
    sha256: &'a str,
    size: u64,
}

#[derive(Facet)]
struct Receipt<'a> {
    files: Vec<ReceiptFile<'a>>,
    manifest_sha256: &'a str,
    outcome: &'static str,
    transaction_id: &'a str,
    version: u32,
}

fn expected_receipt(manifest: &ApprovedManifest, binding: &JournalBinding) -> Result<String> {
    let (digest, transaction) = binding.receipt_context();
    let files = manifest
        .files()
        .map(|file| ReceiptFile {
            id: file.id(),
            sha256: file.sha256(),
            size: file.size(),
        })
        .collect();
    let receipt = facet_json::to_string(&Receipt {
        files,
        manifest_sha256: digest,
        outcome: "published-durability-unconfirmed",
        transaction_id: transaction,
        version: 1,
    })?;
    ensure!(receipt.len() <= 8 * 1024, "receipt exceeds limit");
    Ok(receipt)
}

#[derive(Clone, Facet, PartialEq, Eq)]
#[facet(deny_unknown_fields)]
struct Record {
    binding: JournalBinding,
    event: Event,
    sequence: u64,
    version: u32,
}

/// A retained exclusive journal handle and its validated transaction log.
/// Records must be revalidated on restart; they do not prove access control,
/// a durable publication, or authorization to serve a recorded receipt.
pub struct TransactionJournal {
    lock: ExclusiveFile,
    binding: JournalBinding,
    manifest: ApprovedManifest,
    stage_volume: u32,
    reserved: [ObjectIdentity; 3],
    records: Vec<u8>,
    sequence: u64,
    files: BTreeMap<String, FileEntry>,
    progress: Progress,
    poisoned: bool,
    #[cfg(test)]
    before_receipt: Option<Box<dyn FnOnce() + Send>>,
}

impl std::fmt::Debug for TransactionJournal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransactionJournal")
            .field("sequence", &self.sequence)
            .field("file_count", &self.files.len())
            .field("aborted", &self.progress.aborted)
            .field("has_commit_intent", &self.progress.commit_intent.is_some())
            .field("has_published_record", &self.progress.published.is_some())
            .field("has_receipt", &self.progress.receipt.is_some())
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

fn identity(file: &File) -> Result<ObjectIdentity> {
    let info = regular_file_identity(file)?;
    Ok(ObjectIdentity {
        volume_serial: info.volume_serial,
        file_index: info.file_index,
    })
}

fn encode(record: &Record) -> Result<Vec<u8>> {
    let payload = facet_json::to_string(record)?;
    ensure!(payload.len() <= MAX_FRAME, "journal frame too large");
    let mut frame = Vec::with_capacity(8 + payload.len() + 32);
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&u32::try_from(payload.len())?.to_be_bytes());
    frame.extend_from_slice(payload.as_bytes());
    frame.extend_from_slice(&Sha256::digest(&frame));
    Ok(frame)
}

fn read_log(lock: &mut ExclusiveFile) -> Result<Vec<u8>> {
    lock.verify()?;
    let file = lock.file_mut();
    ensure!(
        file.metadata()?.len() <= MAX_LOG as u64,
        "journal too large"
    );
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.take((MAX_LOG + 1) as u64).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= MAX_LOG, "journal too large");
    Ok(bytes)
}

fn append(lock: &mut ExclusiveFile, frame: &[u8]) -> Result<()> {
    lock.verify()?;
    let file = lock.file_mut();
    file.seek(SeekFrom::End(0))?;
    file.write_all(frame)?;
    file.sync_all()?;
    Ok(())
}

fn approval(
    lock: &ExclusiveFile,
    input: &JournalApproval<'_>,
) -> Result<(JournalBinding, ApprovedManifest)> {
    approval_for_mode(lock, input, false)
}

fn approval_for_mode(
    lock: &ExclusiveFile,
    input: &JournalApproval<'_>,
    local_inspection: bool,
) -> Result<(JournalBinding, ApprovedManifest)> {
    let actual = lock.identity();
    ensure!(
        actual.volume_serial == input.journal_file.volume_serial
            && actual.file_index == input.journal_file.file_index,
        "journal handle identity mismatch"
    );
    let (binding, manifest) = if local_inspection {
        (
            JournalBinding::for_local_inspection(input)?,
            parse_for_local_inspection(
                input.manifest_bytes,
                input.manifest_sha256,
                input.transaction_id,
            )?,
        )
    } else {
        (
            JournalBinding::from_approval(input)?,
            parse_approved_manifest(
                input.manifest_bytes,
                input.manifest_sha256,
                input.transaction_id,
                input.now_unix,
            )?,
        )
    };
    Ok((binding, manifest))
}

fn apply(
    event: &Event,
    manifest: &ApprovedManifest,
    binding: &JournalBinding,
    reserved: &[ObjectIdentity; 3],
    files: &mut BTreeMap<String, FileEntry>,
    progress: &mut Progress,
    sequence: u64,
) -> Result<()> {
    match event {
        Event::Approved => ensure!(
            sequence == 1
                && files.is_empty()
                && !progress.aborted
                && progress.commit_intent.is_none(),
            "invalid initial record"
        ),
        Event::FileClaimed(observation) | Event::FileVerified(observation) => {
            ensure!(
                sequence > 1 && !progress.aborted && progress.commit_intent.is_none(),
                "invalid file record"
            );
            let file = manifest
                .files()
                .find(|f| f.id() == observation.id)
                .ok_or_else(|| eyre::eyre!("file not in manifest"))?;
            ensure!(
                observation.size == file.size()
                    && observation.sha256 == file.sha256()
                    && observation.object.volume_serial == reserved[1].volume_serial
                    && observation.object.file_index != 0
                    && !reserved.contains(&observation.object),
                "file observation mismatch"
            );
            if let Some(entry) = files.get_mut(&observation.id) {
                ensure!(
                    matches!(event, Event::FileVerified(_))
                        && !entry.verified
                        && entry.observation == *observation,
                    "conflicting or duplicate file record"
                );
                entry.verified = true;
            } else {
                ensure!(
                    !files
                        .values()
                        .any(|f| f.observation.object == observation.object),
                    "duplicate file identity"
                );
                // Legacy v2 verified records without an earlier claim remain
                // readable but do not authorize restarting a partial file.
                files.insert(
                    observation.id.clone(),
                    FileEntry {
                        observation: observation.clone(),
                        verified: matches!(event, Event::FileVerified(_)),
                    },
                );
            }
        }
        Event::CommitIntent(stage) => {
            ensure!(
                sequence > 1
                    && !progress.aborted
                    && progress.commit_intent.is_none()
                    && *stage == reserved[1]
                    && files.len() == manifest.files().len()
                    && manifest
                        .files()
                        .all(|file| files.get(file.id()).is_some_and(|entry| entry.verified)),
                "invalid commit intent"
            );
            progress.commit_intent = Some(*stage);
        }
        Event::Aborted => {
            ensure!(
                sequence > 1 && !progress.aborted && progress.commit_intent.is_none(),
                "invalid abort"
            );
            progress.aborted = true;
        }
        Event::Published(stage) => {
            ensure!(
                sequence > 1
                    && !progress.aborted
                    && progress.commit_intent == Some(*stage)
                    && progress.published.is_none()
                    && progress.receipt.is_none(),
                "invalid published record"
            );
            progress.published = Some(*stage);
        }
        Event::ReceiptRecorded(receipt) => {
            ensure!(
                sequence > 1
                    && !progress.aborted
                    && progress.published == progress.commit_intent
                    && progress.published.is_some()
                    && progress.receipt.is_none()
                    && *receipt == expected_receipt(manifest, binding)?,
                "invalid receipt record"
            );
            progress.receipt = Some(receipt.clone());
        }
    }
    Ok(())
}

impl TransactionJournal {
    pub(crate) fn matches_approval(&self, input: &JournalApproval<'_>) -> Result<bool> {
        Ok(self.binding == JournalBinding::from_approval(input)?)
    }

    pub(crate) fn matches_client_pin(&self, pin: &[u8; 32]) -> bool {
        self.binding.matches_client_pin(pin)
    }

    pub(crate) fn matches_server_pin(&self, pin: &[u8; 32]) -> bool {
        self.binding.matches_server_pin(pin)
    }

    /// Initialize an empty file held with zero sharing by `ExclusiveFile`.
    /// A failed write has uncertain outcome and is never automatically repaired.
    ///
    /// # Errors
    /// Returns an error if approval, handle identity, file state or I/O is invalid.
    pub fn initialize(mut lock: ExclusiveFile, input: &JournalApproval<'_>) -> Result<Self> {
        let (binding, manifest) = approval(&lock, input)?;
        ensure!(read_log(&mut lock)?.is_empty(), "journal must be empty");
        let record = Record {
            binding: binding.clone(),
            event: Event::Approved,
            sequence: 1,
            version: 2,
        };
        let frame = encode(&record)?;
        append(&mut lock, &frame)?;
        Ok(Self {
            lock,
            binding,
            manifest,
            stage_volume: input.stage_directory.volume_serial,
            reserved: [
                input.destination_parent,
                input.stage_directory,
                input.journal_file,
            ],
            records: frame,
            sequence: 1,
            files: BTreeMap::new(),
            progress: Progress::default(),
            poisoned: false,
            #[cfg(test)]
            before_receipt: None,
        })
    }

    /// Replay a complete log against the exact local approval. Torn and expired
    /// logs fail closed and remain untouched for local inspection.
    ///
    /// # Errors
    /// Returns an error for an invalid binding, framing, sequence or transition.
    pub fn reopen(lock: ExclusiveFile, input: &JournalApproval<'_>) -> Result<Self> {
        Self::reopen_for_mode(lock, input, false)
    }

    fn reopen_for_mode(
        mut lock: ExclusiveFile,
        input: &JournalApproval<'_>,
        local_inspection: bool,
    ) -> Result<Self> {
        let (binding, manifest) = approval_for_mode(&lock, input, local_inspection)?;
        let bytes = read_log(&mut lock)?;
        ensure!(!bytes.is_empty(), "empty journal");
        let mut offset = 0usize;
        let mut sequence = 0u64;
        let mut files = BTreeMap::new();
        let mut progress = Progress::default();
        while offset < bytes.len() {
            let remaining = &bytes[offset..];
            ensure!(
                remaining.len() >= 40 && &remaining[..4] == MAGIC,
                "incomplete or invalid frame"
            );
            let payload_len = u32::from_be_bytes(remaining[4..8].try_into()?) as usize;
            ensure!(payload_len <= MAX_FRAME, "journal frame too large");
            let body_end = 8usize
                .checked_add(payload_len)
                .ok_or_else(|| eyre::eyre!("frame overflow"))?;
            let frame_end = body_end
                .checked_add(32)
                .ok_or_else(|| eyre::eyre!("frame overflow"))?;
            ensure!(frame_end <= remaining.len(), "incomplete frame");
            ensure!(
                Sha256::digest(&remaining[..body_end])[..] == remaining[body_end..frame_end],
                "journal checksum mismatch"
            );
            let payload = &remaining[8..body_end];
            let record: Record = facet_json::from_slice(payload)
                .map_err(|_e| eyre::eyre!("invalid journal record"))?;
            ensure!(
                facet_json::to_string(&record)?.as_bytes() == payload,
                "noncanonical record"
            );
            sequence = sequence
                .checked_add(1)
                .ok_or_else(|| eyre::eyre!("sequence overflow"))?;
            ensure!(
                record.version == 2 && record.sequence == sequence && record.binding == binding,
                "journal binding or sequence mismatch"
            );
            if sequence == 1 {
                ensure!(record.event == Event::Approved, "missing approval");
            }
            apply(
                &record.event,
                &manifest,
                &binding,
                &[
                    input.destination_parent,
                    input.stage_directory,
                    input.journal_file,
                ],
                &mut files,
                &mut progress,
                sequence,
            )?;
            offset += frame_end;
        }
        Ok(Self {
            lock,
            binding,
            manifest,
            stage_volume: input.stage_directory.volume_serial,
            reserved: [
                input.destination_parent,
                input.stage_directory,
                input.journal_file,
            ],
            records: bytes,
            sequence,
            files,
            progress,
            poisoned: false,
            #[cfg(test)]
            before_receipt: None,
        })
    }

    fn persist(&mut self, event: Event, now: u64) -> Result<()> {
        self.persist_with_clock(event, &|| Ok(now))
    }

    fn persist_with_clock(&mut self, event: Event, clock: &impl Fn() -> Result<u64>) -> Result<()> {
        ensure!(
            !self.poisoned && !self.progress.aborted,
            "journal unavailable"
        );
        ensure!(clock()? < self.manifest.expires_unix(), "approval expired");
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| eyre::eyre!("sequence overflow"))?;
        let mut files = self.files.clone();
        let mut progress = self.progress.clone();
        apply(
            &event,
            &self.manifest,
            &self.binding,
            &self.reserved,
            &mut files,
            &mut progress,
            sequence,
        )?;
        let frame = encode(&Record {
            binding: self.binding.clone(),
            event,
            sequence,
            version: 2,
        })?;
        ensure!(
            self.records
                .len()
                .checked_add(frame.len())
                .is_some_and(|len| len <= MAX_LOG),
            "journal exceeds limit"
        );
        self.poisoned = true;
        ensure!(
            read_log(&mut self.lock)? == self.records,
            "journal changed while held"
        );
        ensure!(clock()? < self.manifest.expires_unix(), "approval expired");
        append(&mut self.lock, &frame)?;
        // A write or sync can finish after the caller timed out. Leave this
        // instance poisoned and the on-disk outcome for explicit inspection.
        ensure!(clock()? < self.manifest.expires_unix(), "approval expired");
        self.records.extend(frame);
        self.files = files;
        self.progress = progress;
        self.sequence = sequence;
        self.poisoned = false;
        Ok(())
    }

    /// Record an empty, exclusively held file before any body is written.
    /// This records identity only; it does not prove safe staging or permit
    /// deleting or truncating a partial file after a crash.
    ///
    /// # Errors
    /// Returns an error for unsafe, nonempty, conflicting or expired inputs.
    pub fn claim_empty_file(&mut self, id: &str, file: &mut ExclusiveFile, now: u64) -> Result<()> {
        self.claim_empty_file_inner(id, file, &|| Ok(now))
    }

    pub(crate) fn claim_empty_file_before(
        &mut self,
        id: &str,
        file: &mut ExclusiveFile,
        deadline: std::time::Instant,
        gate: &BlockingIoGate,
    ) -> Result<()> {
        self.claim_empty_file_inner(id, file, &|| {
            gate.ensure_active()?;
            ensure!(
                std::time::Instant::now() < deadline,
                "claim deadline expired"
            );
            Ok(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs())
        })
    }

    fn claim_empty_file_inner(
        &mut self,
        id: &str,
        file: &mut ExclusiveFile,
        clock: &impl Fn() -> Result<u64>,
    ) -> Result<()> {
        ensure!(
            !self.poisoned
                && !self.progress.aborted
                && self.progress.commit_intent.is_none()
                && clock()? < self.manifest.expires_unix(),
            "journal unavailable"
        );
        self.lock.verify()?;
        ensure!(clock()? < self.manifest.expires_unix(), "approval expired");
        file.verify()?;
        ensure!(clock()? < self.manifest.expires_unix(), "approval expired");
        let approved = self
            .manifest
            .files()
            .find(|f| f.id() == id)
            .ok_or_else(|| eyre::eyre!("unknown file"))?;
        let object = identity(file.file_mut())?;
        ensure!(
            object.volume_serial == self.stage_volume && !self.reserved.contains(&object),
            "file identity is outside the approved volume or reserved"
        );
        ensure!(
            file.file_mut().metadata()?.len() == 0,
            "file is not empty; inspect partial data"
        );
        let observation = FileObservation {
            id: id.to_owned(),
            object,
            size: approved.size(),
            sha256: approved.sha256().to_owned(),
        };
        if let Some(existing) = self.files.get(id) {
            ensure!(
                !existing.verified && existing.observation == observation,
                "conflicting file claim"
            );
            return Ok(());
        }
        ensure!(clock()? < self.manifest.expires_unix(), "approval expired");
        file.file_mut().sync_all()?;
        ensure!(clock()? < self.manifest.expires_unix(), "approval expired");
        file.verify()?;
        self.persist_with_clock(Event::FileClaimed(observation), clock)
    }

    /// Verify a retained file handle's identity, exact length and digest, sync
    /// it, then record its observed identity. A repeat succeeds only for the
    /// same identity after re-verification. This does not establish containment.
    ///
    /// # Errors
    /// Returns an error on mismatch, expiry, invalid identity or I/O failure.
    pub fn verify_file(&mut self, id: &str, file: &mut File, now: u64) -> Result<()> {
        self.verify_file_inner(id, file, &|| Ok(now), false)
    }

    pub(crate) fn verify_file_before(
        &mut self,
        id: &str,
        file: &mut File,
        deadline: std::time::Instant,
        gate: &BlockingIoGate,
    ) -> Result<()> {
        self.verify_file_inner(
            id,
            file,
            &|| {
                gate.ensure_active()?;
                ensure!(
                    std::time::Instant::now() < deadline,
                    "verification deadline expired"
                );
                Ok(std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs())
            },
            false,
        )
    }

    /// Recheck a previously verified file after commit intent was recorded.
    /// This checks its retained identity, length and hash without appending to
    /// the journal. It does not identify a final directory, establish an exact
    /// file set, reconcile an ambiguous rename, or authorize a receipt.
    ///
    /// # Errors
    /// Returns an error if intent or the prior observation is missing, or if
    /// identity, content, expiry, or I/O checks fail.
    pub fn reverify_intent_file(&mut self, id: &str, file: &mut File, now: u64) -> Result<()> {
        ensure!(
            self.progress.commit_intent.is_some(),
            "commit intent is missing"
        );
        ensure!(
            self.files.get(id).is_some_and(|entry| entry.verified),
            "prior verified file observation is missing"
        );
        self.verify_file_inner(id, file, &|| Ok(now), true)
    }

    fn verify_file_inner(
        &mut self,
        id: &str,
        file: &mut File,
        clock: &impl Fn() -> Result<u64>,
        allow_intent: bool,
    ) -> Result<()> {
        ensure!(
            !self.poisoned
                && !self.progress.aborted
                && (allow_intent || self.progress.commit_intent.is_none())
                && clock()? < self.manifest.expires_unix(),
            "journal unavailable"
        );
        let approved = self
            .manifest
            .files()
            .find(|f| f.id() == id)
            .ok_or_else(|| eyre::eyre!("unknown file"))?;
        let object = identity(file)?;
        ensure!(
            object.volume_serial == self.stage_volume,
            "file is on another volume"
        );
        ensure!(
            !self.reserved.contains(&object),
            "file identity is reserved"
        );
        self.lock.verify()?;
        let observation = FileObservation {
            id: id.to_owned(),
            object,
            size: approved.size(),
            sha256: approved.sha256().to_owned(),
        };
        if let Some(existing) = self.files.get(id) {
            ensure!(
                existing.observation == observation,
                "conflicting file identity"
            );
        }
        let stream_identity = super::windows_lock::FileIdentity {
            volume_serial: object.volume_serial,
            file_index: object.file_index,
        };
        ensure!(clock()? < self.manifest.expires_unix(), "approval expired");
        super::windows_streams::verify_file_streams(file, stream_identity, approved.size())?;
        ensure!(clock()? < self.manifest.expires_unix(), "approval expired");
        file.seek(SeekFrom::Start(0))?;
        let mut verifier = FileVerifier::new(approved, std::io::sink());
        let mut buf = [0u8; 16 * 1024];
        loop {
            ensure!(
                clock()? < self.manifest.expires_unix(),
                "verification authorization expired"
            );
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            verifier.push(&buf[..n])?;
        }
        verifier.finish()?;
        file.sync_all()?;
        ensure!(clock()? < self.manifest.expires_unix(), "approval expired");
        super::windows_streams::verify_file_streams(file, stream_identity, approved.size())?;
        ensure!(identity(file)? == object, "file identity changed");
        ensure!(
            clock()? < self.manifest.expires_unix(),
            "verification authorization expired"
        );
        if self.files.get(id).is_some_and(|entry| entry.verified) {
            return Ok(());
        }
        self.persist_with_clock(Event::FileVerified(observation), clock)
    }

    /// Persist cancellation without removing any file.
    ///
    /// # Errors
    /// Returns an error on expiry, state conflict or I/O failure.
    pub fn abort(&mut self, now: u64) -> Result<()> {
        self.persist(Event::Aborted, now)
    }

    /// Whether the log includes a prior observation, not a current integrity proof.
    #[must_use]
    pub fn has_observation(&self, id: &str) -> bool {
        self.files.get(id).is_some_and(|entry| entry.verified)
    }

    /// Whether an unverified file identity was recorded before its body.
    /// A partial file must still be inspected and is never truncated here.
    #[must_use]
    pub fn has_pending_claim(&self, id: &str) -> bool {
        self.files.get(id).is_some_and(|entry| !entry.verified)
    }

    /// Persist the approved stage identity as a commit intent after every file
    /// has an observation. This does not prove that the files are still safe,
    /// authorize a rename, establish its outcome, or create a receipt. A real
    /// publisher must independently revalidate its held handles and access gates.
    /// Once intent is recorded this instance cannot receive more data or abort;
    /// recovery must inspect the stage and destination without inferring success.
    ///
    /// # Errors
    /// Returns an error if observations are missing, the journal is unavailable,
    /// the approval expired, or writing and syncing the record fails.
    pub fn record_commit_intent(&mut self, now: u64) -> Result<()> {
        self.persist(Event::CommitIntent(self.reserved[1]), now)
    }

    /// Recheck a held staged file set and persist commit intent under a running
    /// single-flight blocking-I/O gate. This is not a publication permit: the
    /// caller must separately qualify and retain trusted ancestry, stage and
    /// destination handles, access controls and filesystem semantics.
    ///
    /// The worker must own the journal, stage and file handles until it exits.
    /// A timeout or cancellation can occur during an OS call or journal sync;
    /// treat the outcome as uncertain and require local inspection, never a
    /// concurrent retry. Child handles remain held on success.
    ///
    /// # Errors
    /// Rejects expired approval, unsafe or mismatched stage/files, unexpected
    /// entries, changed contents, deadline expiry and journal failures.
    pub fn prepare_staged_commit_before(
        &mut self,
        stage: &File,
        files: &mut BTreeMap<String, ExclusiveFile>,
        deadline: std::time::Instant,
        gate: &BlockingIoGate,
    ) -> Result<()> {
        use super::windows_lock::FileIdentity;
        use super::windows_stage::{ExpectedEntry, verify_entries};

        let expiry = self.manifest.expires_unix();
        let checkpoint = || -> Result<u64> {
            gate.ensure_active()?;
            ensure!(
                std::time::Instant::now() < deadline,
                "commit preparation deadline expired"
            );
            let current = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            ensure!(current < expiry, "approval expired");
            Ok(current)
        };
        checkpoint()?;
        self.lock.verify()?;
        let stage_id = directory_identity(stage)?;
        ensure!(
            stage_id
                == FileIdentity {
                    volume_serial: self.reserved[1].volume_serial,
                    file_index: self.reserved[1].file_index,
                },
            "stage identity mismatch"
        );
        checkpoint()?;
        super::windows_streams::verify_directory_streams(stage, stage_id)?;
        checkpoint()?;
        ensure!(
            files.len() == self.manifest.files().len(),
            "file set mismatch"
        );
        let approved: Vec<_> = self
            .manifest
            .files()
            .map(|item| (item.id().to_owned(), item.name().to_owned(), item.size()))
            .collect();
        let mut entries = Vec::with_capacity(approved.len());
        for (id, name, size) in &approved {
            ensure!(self.has_observation(id), "file observation missing");
            let file = files
                .get(id)
                .ok_or_else(|| eyre::eyre!("missing staged file"))?;
            file.verify()?;
            entries.push(ExpectedEntry {
                name,
                identity: file.identity(),
                size: *size,
            });
        }
        verify_entries(stage, stage_id, &entries)?;
        checkpoint()?;
        for (id, _, _) in &approved {
            let file = files
                .get_mut(id)
                .ok_or_else(|| eyre::eyre!("missing staged file"))?;
            file.verify()?;
            self.verify_file_before(id, file.file_mut(), deadline, gate)?;
            file.verify()?;
        }
        verify_entries(stage, stage_id, &entries)?;
        checkpoint()?;
        super::windows_streams::verify_directory_streams(stage, stage_id)?;
        let current = checkpoint()?;
        self.record_commit_intent(current)?;
        checkpoint()?;
        Ok(())
    }

    /// Reopen the renamed directory's exact approved file set by held parent
    /// handle, then recheck identities, lengths, hashes and streams. This is
    /// not a publication permit or proof of protected ancestry. The returned
    /// exclusive handles must stay live through the receipt decision.
    pub(crate) fn verify_post_rename_files_before(
        &mut self,
        stage: &File,
        deadline: std::time::Instant,
        gate: &BlockingIoGate,
    ) -> Result<BTreeMap<String, ExclusiveFile>> {
        use super::windows_acl::reopen_private_file_no_share;
        use super::windows_lock::FileIdentity;
        use super::windows_stage::{ExpectedEntry, verify_entries};

        let expiry = self.manifest.expires_unix();
        let checkpoint = || -> Result<u64> {
            gate.ensure_active()?;
            ensure!(
                std::time::Instant::now() < deadline,
                "post-rename deadline expired"
            );
            let current = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            ensure!(current < expiry, "approval expired");
            Ok(current)
        };
        checkpoint()?;
        self.lock.verify()?;
        ensure!(
            self.intent_matches_directory(stage)?,
            "stage identity mismatch"
        );
        let stage_id = directory_identity(stage)?;
        let mut expected = Vec::new();
        for approved in self.manifest.files() {
            let recorded = self
                .files
                .get(approved.id())
                .ok_or_else(|| eyre::eyre!("missing observation"))?;
            ensure!(recorded.verified, "file observation is not verified");
            expected.push((
                approved.id().to_owned(),
                approved.name().to_owned(),
                approved.size(),
                FileIdentity {
                    volume_serial: recorded.observation.object.volume_serial,
                    file_index: recorded.observation.object.file_index,
                },
            ));
        }
        ensure!(expected.len() == self.files.len(), "file set mismatch");
        let entries: Vec<_> = expected
            .iter()
            .map(|(_, name, size, identity)| ExpectedEntry {
                name,
                identity: *identity,
                size: *size,
            })
            .collect();
        checkpoint()?;
        super::windows_streams::verify_directory_streams(stage, stage_id)?;
        checkpoint()?;
        verify_entries(stage, stage_id, &entries)?;
        let mut held = BTreeMap::new();
        for (id, name, _, identity) in &expected {
            checkpoint()?;
            let mut file = reopen_private_file_no_share(stage, stage_id, name, *identity)?;
            checkpoint()?;
            self.verify_file_inner(id, file.file_mut(), &checkpoint, true)?;
            checkpoint()?;
            ensure!(held.insert(id.clone(), file).is_none(), "duplicate file ID");
        }
        checkpoint()?;
        verify_entries(stage, stage_id, &entries)?;
        checkpoint()?;
        super::windows_streams::verify_directory_streams(stage, stage_id)?;
        checkpoint()?;
        self.lock.verify()?;
        ensure!(
            self.intent_matches_directory(stage)?,
            "stage identity changed"
        );
        Ok(held)
    }

    /// The journaled pre-rename identity, if commit intent was recorded.
    /// This is not evidence that a rename took place.
    #[must_use]
    pub const fn commit_intent_stage(&self) -> Option<ObjectIdentity> {
        self.progress.commit_intent
    }

    /// Compare a retained, non-reparse directory handle to the recorded
    /// pre-rename stage identity. A match alone does not prove containment,
    /// access control, exact contents, a rename, or permission for a receipt.
    ///
    /// # Errors
    /// Returns an error if commit intent is absent or the handle is unsafe.
    pub fn intent_matches_directory(&self, directory: &File) -> Result<bool> {
        let recorded = self
            .progress
            .commit_intent
            .ok_or_else(|| eyre::eyre!("commit intent is missing"))?;
        let actual = directory_identity(directory)?;
        Ok(actual.volume_serial == recorded.volume_serial
            && actual.file_index == recorded.file_index)
    }

    /// Recheck the held journal and approved parent, stage and final component
    /// before a gated rename. This is not evidence of safe staging or ancestry.
    pub(crate) fn check_publication_binding(
        &mut self,
        parent: &File,
        stage: &File,
        name: &str,
    ) -> Result<()> {
        self.check_publication_time()?;
        ensure!(
            self.progress.published.is_none() && self.progress.receipt.is_none(),
            "publication already recorded"
        );
        self.lock.verify()?;
        ensure!(
            read_log(&mut self.lock)? == self.records,
            "journal changed while held"
        );
        let parent_id = directory_identity(parent)?;
        ensure!(
            self.binding.matches_publication_target(
                ObjectIdentity {
                    volume_serial: parent_id.volume_serial,
                    file_index: parent_id.file_index,
                },
                name
            ),
            "publication parent or final name does not match approval"
        );
        ensure!(
            self.intent_matches_directory(stage)?,
            "stage identity does not match commit intent"
        );
        self.check_publication_time()
    }

    /// Recheck the approved held target before recording a new commit intent.
    /// This is an identity/binding check, not an ancestry qualification.
    pub(crate) fn check_pre_intent_target(
        &mut self,
        parent: &File,
        stage: &File,
        name: &str,
    ) -> Result<()> {
        ensure!(
            self.progress.commit_intent.is_none(),
            "commit intent already recorded"
        );
        self.check_publication_time()?;
        self.lock.verify()?;
        ensure!(
            read_log(&mut self.lock)? == self.records,
            "journal changed while held"
        );
        let parent_id = directory_identity(parent)?;
        ensure!(
            self.binding.matches_publication_target(
                ObjectIdentity {
                    volume_serial: parent_id.volume_serial,
                    file_index: parent_id.file_index,
                },
                name,
            ),
            "publication parent or final name does not match approval"
        );
        let stage_id = directory_identity(stage)?;
        ensure!(
            stage_id.volume_serial == self.reserved[1].volume_serial
                && stage_id.file_index == self.reserved[1].file_index,
            "stage identity does not match approval"
        );
        self.check_publication_time()
    }

    /// Recheck the absolute approval deadline immediately before issuing a
    /// gated rename. A rename that completes after expiry is still an observed
    /// filesystem change and must be reconciled without assuming a receipt.
    pub(crate) fn check_publication_time(&self) -> Result<()> {
        ensure!(
            !self.poisoned && !self.progress.aborted,
            "journal unavailable"
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        ensure!(now < self.manifest.expires_unix(), "approval expired");
        Ok(())
    }

    /// A non-success rename may have changed the namespace; keep this instance
    /// unusable and require local reconciliation under a newly acquired lock.
    pub(crate) fn mark_publication_uncertain(&mut self) {
        self.poisoned = true;
    }

    pub(crate) fn approved_journal_identity(&self) -> ObjectIdentity {
        self.reserved[2]
    }

    /// Re-read a recorded receipt after the caller has established a separate
    /// qualified replay permit. This does not itself validate a final directory
    /// or authorize a client. The live path remains gated by that permit.
    pub(crate) fn read_recorded_receipt_before(
        &mut self,
        deadline: std::time::Instant,
        gate: &BlockingIoGate,
    ) -> Result<Vec<u8>> {
        let expiry = self.manifest.expires_unix();
        let checkpoint = || {
            gate.ensure_active()?;
            ensure!(
                std::time::Instant::now() < deadline,
                "receipt deadline expired"
            );
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            ensure!(now < expiry, "approval expired");
            Ok(())
        };
        ensure!(
            !self.poisoned && !self.progress.aborted,
            "journal unavailable"
        );
        ensure!(
            self.progress.published.is_some()
                && self.progress.published == self.progress.commit_intent,
            "published record missing"
        );
        let receipt = self
            .progress
            .receipt
            .clone()
            .ok_or_else(|| eyre::eyre!("receipt missing"))?;
        ensure!(
            receipt == expected_receipt(&self.manifest, &self.binding)?,
            "receipt mismatch"
        );
        checkpoint()?;
        self.lock.verify()?;
        checkpoint()?;
        ensure!(
            read_log(&mut self.lock)? == self.records,
            "journal changed while held"
        );
        checkpoint()?;
        Ok(receipt.into_bytes())
    }

    /// Persist a successful, locally observed publication and deterministic
    /// unconfirmed-durability receipt. This method is reachable only with the
    /// private evidence produced by the still-gated rename implementation.
    /// A failed or expired write poisons this journal and requires recovery.
    pub(crate) fn record_observed_publication(
        &mut self,
        evidence: super::windows_publish::ObservedPublication,
        gate: &BlockingIoGate,
        deadline: std::time::Instant,
    ) -> Result<()> {
        let operation = (|| {
            ensure!(
                evidence.matches(
                    self.reserved[0],
                    self.reserved[1],
                    self.reserved[2],
                    &self.binding
                ),
                "publication evidence mismatch"
            );
            let clock = || {
                gate.ensure_active()?;
                ensure!(
                    std::time::Instant::now() < deadline,
                    "publication deadline expired"
                );
                Ok(std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs())
            };
            self.persist_with_clock(Event::Published(self.reserved[1]), &clock)?;
            #[cfg(test)]
            if let Some(hook) = self.before_receipt.take() {
                hook();
            }
            let receipt = expected_receipt(&self.manifest, &self.binding)?;
            self.persist_with_clock(Event::ReceiptRecorded(receipt), &clock)
        })();
        if operation.is_err() {
            self.poisoned = true;
        }
        operation
    }

    #[cfg(test)]
    pub(crate) fn recorded_receipt(&self) -> Option<&str> {
        self.progress.receipt.as_deref()
    }

    #[cfg(test)]
    pub(crate) fn has_published_record(&self) -> bool {
        self.progress.published.is_some()
    }

    #[cfg(test)]
    pub(crate) fn set_before_receipt(&mut self, hook: Box<dyn FnOnce() + Send>) {
        self.before_receipt = Some(hook);
    }

    /// Operational publication and receipt replay remain unavailable.
    ///
    /// # Errors
    /// Always returns an error until the reviewed publication gates exist.
    pub fn commit(&self) -> Result<()> {
        bail!("publication is disabled")
    }
}

/// Read-only local inspection of a transaction, including after its transfer
/// approval expired. This wrapper never yields the live journal, writes a
/// record, returns receipt bytes, starts a listener, or authorizes publication.
/// Its identity and hash checks do not qualify ancestry or establish that a
/// directory is the approved final name. Callers must independently establish
/// those properties and run potentially blocking operations under a deadline.
#[derive(Debug)]
pub struct LocalInspection {
    journal: TransactionJournal,
}

/// Owned result of a bounded read-only inspection. Holding this value retains
/// the journal lock, parent, final-directory and file handles, but does not
/// qualify ancestry, exclude pre-existing handles, or authorize replay or publication.
#[derive(Debug)]
pub struct InspectionSnapshot {
    inspection: LocalInspection,
    parent: File,
    final_directory: File,
    files: BTreeMap<String, ExclusiveFile>,
}

impl InspectionSnapshot {
    /// Return the held resources for further local inspection.
    #[must_use]
    pub fn into_parts(self) -> (LocalInspection, File, File, BTreeMap<String, ExclusiveFile>) {
        (
            self.inspection,
            self.parent,
            self.final_directory,
            self.files,
        )
    }
}

struct ExpectedInspectionFile {
    id: String,
    name: String,
    identity: super::windows_lock::FileIdentity,
    size: u64,
}

impl LocalInspection {
    /// Reopen a locally selected journal under its exclusive lock. Expiry is
    /// not treated as live authorization; all other manifest, pin, identity,
    /// framing and sequence validation still applies, and the file is not repaired.
    ///
    /// # Errors
    /// Rejects mismatched local approval, unsafe lock, malformed or torn logs.
    pub fn open(lock: ExclusiveFile, approval: &JournalApproval<'_>) -> Result<Self> {
        Ok(Self {
            journal: TransactionJournal::reopen_for_mode(lock, approval, true)?,
        })
    }

    /// Describe what local examination is needed, not whether it succeeded.
    #[must_use]
    pub const fn disposition(&self) -> super::recovery::RecoveryDisposition {
        use super::recovery::RecoveryDisposition;
        let progress = &self.journal.progress;
        if progress.aborted {
            RecoveryDisposition::InspectAborted
        } else if progress.published.is_some() {
            RecoveryDisposition::InspectPublished
        } else if progress.commit_intent.is_some() {
            RecoveryDisposition::InspectAmbiguousPublication
        } else {
            RecoveryDisposition::InspectStaging
        }
    }

    /// Compare a retained directory to the commit-intent identity. A match is
    /// not sufficient to infer that publication occurred or authorize a receipt.
    ///
    /// # Errors
    /// Rejects a missing intent or invalid directory handle.
    pub fn intent_matches_directory(&self, directory: &File) -> Result<bool> {
        self.journal.intent_matches_directory(directory)
    }

    /// Recheck an exclusively held, previously observed file's identity,
    /// exact length and SHA-256 without writing the file or journal. This does
    /// not prove containment, a complete file set, or safe access by others.
    ///
    /// # Errors
    /// Rejects absent intent, unknown or unverified files, identity changes,
    /// digest or length mismatches, and read errors.
    pub fn verify_recorded_file(&mut self, id: &str, file: &mut ExclusiveFile) -> Result<()> {
        self.verify_recorded_file_with(id, file, &|| Ok(()))
    }

    fn verify_recorded_file_with(
        &mut self,
        id: &str,
        file: &mut ExclusiveFile,
        checkpoint: &impl Fn() -> Result<()>,
    ) -> Result<()> {
        checkpoint()?;
        ensure!(
            self.journal.progress.commit_intent.is_some(),
            "commit intent is missing"
        );
        let entry = self
            .journal
            .files
            .get(id)
            .ok_or_else(|| eyre::eyre!("file observation missing"))?;
        ensure!(entry.verified, "file observation is not verified");
        let expected_identity = entry.observation.object;
        let approved = self
            .journal
            .manifest
            .files()
            .find(|candidate| candidate.id() == id)
            .ok_or_else(|| eyre::eyre!("unknown file"))?;
        self.journal.lock.verify()?;
        file.verify()?;
        ensure!(
            identity(file.file_mut())? == expected_identity,
            "file identity mismatch"
        );
        let file_identity = file.identity();
        checkpoint()?;
        super::windows_streams::verify_file_streams(
            file.file_mut(),
            file_identity,
            approved.size(),
        )?;
        checkpoint()?;
        file.file_mut().seek(SeekFrom::Start(0))?;
        let mut verifier = FileVerifier::new(approved, std::io::sink());
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            checkpoint()?;
            let count = file.file_mut().read(&mut buffer)?;
            checkpoint()?;
            if count == 0 {
                break;
            }
            verifier.push(&buffer[..count])?;
        }
        verifier.finish()?;
        checkpoint()?;
        super::windows_streams::verify_file_streams(
            file.file_mut(),
            file_identity,
            approved.size(),
        )?;
        checkpoint()?;
        file.verify()?;
        ensure!(
            identity(file.file_mut())? == expected_identity,
            "file identity changed"
        );
        Ok(())
    }

    /// Inspect the recorded final component relative to its approved parent,
    /// compare the exact set of names, sizes and identities, and rehash every
    /// supplied exclusively held file. The caller must retain the parent and
    /// file handles and serialize directory enumeration for the entire call.
    ///
    /// This is not a qualification token: it does not establish protected
    /// ancestry, exclude pre-existing handles or privileged users, prove crash
    /// durability, return a receipt, or authorize network access. Run this
    /// potentially blocking operation under an owner-controlled deadline.
    ///
    /// # Errors
    /// Rejects missing intent, a changed journal, wrong parent or final identity,
    /// unexpected/missing files, unsafe handles, and content mismatches.
    pub fn inspect_final_contents(
        &mut self,
        parent: &File,
        files: &mut BTreeMap<String, ExclusiveFile>,
    ) -> Result<()> {
        self.inspect_final_contents_with(parent, files, &|| Ok(()))
            .map(drop)
    }

    /// Inspect under a single-flight deadline while moving all supplied handles
    /// into the blocking worker. Timeout or cancellation cannot cancel a kernel
    /// call: its worker retains the handles until that call returns, and the
    /// gate is poisoned. A successful result is still only local inspection.
    ///
    /// # Errors
    /// Rejects unsafe or changed contents, a busy/poisoned gate, or timeout.
    pub async fn inspect_final_contents_bounded(
        self,
        parent: File,
        files: BTreeMap<String, ExclusiveFile>,
        gate: BlockingIoGate,
        budget: std::time::Duration,
    ) -> Result<InspectionSnapshot> {
        self.inspect_final_contents_bounded_inner(parent, files, gate, budget, None)
            .await
    }

    #[cfg(test)]
    pub(crate) async fn inspect_final_contents_with_stall(
        self,
        parent: File,
        files: BTreeMap<String, ExclusiveFile>,
        gate: BlockingIoGate,
        budget: std::time::Duration,
        hook: Box<dyn FnOnce() + Send>,
    ) -> Result<InspectionSnapshot> {
        self.inspect_final_contents_bounded_inner(parent, files, gate, budget, Some(hook))
            .await
    }

    async fn inspect_final_contents_bounded_inner(
        self,
        parent: File,
        files: BTreeMap<String, ExclusiveFile>,
        gate: BlockingIoGate,
        budget: std::time::Duration,
        before_inspection: Option<Box<dyn FnOnce() + Send>>,
    ) -> Result<InspectionSnapshot> {
        ensure!(
            !budget.is_zero() && budget <= std::time::Duration::from_secs(30),
            "inspection budget must be between zero and 30 seconds"
        );
        let deadline = std::time::Instant::now()
            .checked_add(budget)
            .ok_or_else(|| eyre::eyre!("inspection deadline overflow"))?;
        let worker_gate = gate.clone();
        gate.run(budget, move || {
            let checkpoint = || {
                worker_gate.ensure_active()?;
                ensure!(
                    std::time::Instant::now() < deadline,
                    "inspection deadline expired"
                );
                Ok(())
            };
            let mut inspection = self;
            let mut files = files;
            checkpoint()?;
            if let Some(hook) = before_inspection {
                hook();
            }
            checkpoint()?;
            let final_directory =
                inspection.inspect_final_contents_with(&parent, &mut files, &checkpoint)?;
            checkpoint()?;
            Ok(InspectionSnapshot {
                inspection,
                parent,
                final_directory,
                files,
            })
        })
        .await
    }

    #[expect(
        clippy::too_many_lines,
        reason = "keep final identity, stream and file checks in their checkpoint order"
    )]
    fn inspect_final_contents_with(
        &mut self,
        parent: &File,
        files: &mut BTreeMap<String, ExclusiveFile>,
        checkpoint: &impl Fn() -> Result<()>,
    ) -> Result<File> {
        use super::windows_acl::open_downloads_final;
        use super::windows_lock::FileIdentity;
        use super::windows_stage::{ExpectedEntry, verify_entries};

        checkpoint()?;
        ensure!(
            self.journal.progress.commit_intent.is_some(),
            "commit intent is missing"
        );
        ensure!(
            files.len() == self.journal.manifest.files().len(),
            "file set mismatch"
        );
        ensure!(
            read_log(&mut self.journal.lock)? == self.journal.records,
            "journal changed while held"
        );
        checkpoint()?;
        let actual_parent = directory_identity(parent)?;
        let expected_parent = self.journal.reserved[0];
        ensure!(
            actual_parent.volume_serial == expected_parent.volume_serial
                && actual_parent.file_index == expected_parent.file_index,
            "parent identity mismatch"
        );
        checkpoint()?;
        super::windows_streams::verify_directory_streams(parent, actual_parent)?;
        let final_name = self.journal.binding.final_component().to_owned();
        checkpoint()?;
        let final_directory = open_downloads_final(parent, actual_parent, &final_name)?;
        checkpoint()?;
        ensure!(
            self.intent_matches_directory(&final_directory)?,
            "final directory identity mismatch"
        );
        let stage = self.journal.reserved[1];
        let stage_id = FileIdentity {
            volume_serial: stage.volume_serial,
            file_index: stage.file_index,
        };
        let mut expected = Vec::with_capacity(files.len());
        for approved in self.journal.manifest.files() {
            let entry = self
                .journal
                .files
                .get(approved.id())
                .ok_or_else(|| eyre::eyre!("file observation missing"))?;
            ensure!(
                entry.verified && files.contains_key(approved.id()),
                "file set mismatch"
            );
            expected.push(ExpectedInspectionFile {
                id: approved.id().to_owned(),
                name: approved.name().to_owned(),
                identity: FileIdentity {
                    volume_serial: entry.observation.object.volume_serial,
                    file_index: entry.observation.object.file_index,
                },
                size: approved.size(),
            });
        }
        let entries: Vec<_> = expected
            .iter()
            .map(|item| ExpectedEntry {
                name: item.name.as_str(),
                identity: item.identity,
                size: item.size,
            })
            .collect();
        checkpoint()?;
        verify_entries(&final_directory, stage_id, &entries)?;
        checkpoint()?;
        super::windows_streams::verify_directory_streams(&final_directory, stage_id)?;
        checkpoint()?;
        for item in &expected {
            let file = files
                .get_mut(&item.id)
                .ok_or_else(|| eyre::eyre!("file set mismatch"))?;
            self.verify_recorded_file_with(&item.id, file, checkpoint)?;
        }
        checkpoint()?;
        verify_entries(&final_directory, stage_id, &entries)?;
        checkpoint()?;
        super::windows_streams::verify_directory_streams(&final_directory, stage_id)?;
        checkpoint()?;
        super::windows_streams::verify_directory_streams(parent, actual_parent)?;
        checkpoint()?;
        let reopened = open_downloads_final(parent, actual_parent, &final_name)?;
        checkpoint()?;
        ensure!(
            directory_identity(&reopened)? == stage_id,
            "final directory edge changed"
        );
        ensure!(
            directory_identity(parent)? == actual_parent,
            "parent identity changed"
        );
        ensure!(
            read_log(&mut self.journal.lock)? == self.journal.records,
            "journal changed while held"
        );
        checkpoint()?;
        Ok(final_directory)
    }
}

#[cfg(test)]
mod publication_tests {
    use super::*;

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "keep the complete publication and receipt transition sequence together"
    )]
    fn receipt_transition_requires_matching_published_identity_and_canonical_bytes() {
        let id = "0123456789abcdef0123456789abcdef";
        let pin = "1111111111111111111111111111111111111111111111111111111111111111";
        let hash = format!("{:x}", Sha256::digest(b"hello"));
        let raw = format!(
            r#"{{"aggregate_bytes":5,"expires_unix":100,"file_count":1,"files":[{{"id":"one","name":"one.bin","sha256":"{hash}","size":5}}],"transaction_id":"{id}","version":1}}"#
        );
        let digest = format!("{:x}", Sha256::digest(raw.as_bytes()));
        let parent = ObjectIdentity {
            volume_serial: 1,
            file_index: 1,
        };
        let stage = ObjectIdentity {
            volume_serial: 1,
            file_index: 2,
        };
        let journal = ObjectIdentity {
            volume_serial: 1,
            file_index: 3,
        };
        let approval = JournalApproval {
            manifest_bytes: raw.as_bytes(),
            manifest_sha256: &digest,
            transaction_id: id,
            client_pin: pin,
            server_pin: pin,
            destination_parent: parent,
            stage_directory: stage,
            journal_file: journal,
            final_name: "published",
            now_unix: 1,
        };
        let manifest = parse_approved_manifest(raw.as_bytes(), &digest, id, 1).unwrap();
        let binding = JournalBinding::from_approval(&approval).unwrap();
        let reserved = [parent, stage, journal];
        let mut files = BTreeMap::new();
        let mut progress = Progress::default();
        apply(
            &Event::Approved,
            &manifest,
            &binding,
            &reserved,
            &mut files,
            &mut progress,
            1,
        )
        .unwrap();
        let observation = FileObservation {
            id: "one".into(),
            object: ObjectIdentity {
                volume_serial: 1,
                file_index: 4,
            },
            sha256: hash,
            size: 5,
        };
        apply(
            &Event::FileVerified(observation),
            &manifest,
            &binding,
            &reserved,
            &mut files,
            &mut progress,
            2,
        )
        .unwrap();
        apply(
            &Event::CommitIntent(stage),
            &manifest,
            &binding,
            &reserved,
            &mut files,
            &mut progress,
            3,
        )
        .unwrap();
        let receipt = expected_receipt(&manifest, &binding).unwrap();
        let _premature = apply(
            &Event::ReceiptRecorded(receipt.clone()),
            &manifest,
            &binding,
            &reserved,
            &mut files,
            &mut progress,
            4,
        )
        .unwrap_err();
        let _wrong = apply(
            &Event::Published(parent),
            &manifest,
            &binding,
            &reserved,
            &mut files,
            &mut progress,
            4,
        )
        .unwrap_err();
        apply(
            &Event::Published(stage),
            &manifest,
            &binding,
            &reserved,
            &mut files,
            &mut progress,
            4,
        )
        .unwrap();
        let _forged = apply(
            &Event::ReceiptRecorded("forged".into()),
            &manifest,
            &binding,
            &reserved,
            &mut files,
            &mut progress,
            5,
        )
        .unwrap_err();
        apply(
            &Event::ReceiptRecorded(receipt.clone()),
            &manifest,
            &binding,
            &reserved,
            &mut files,
            &mut progress,
            5,
        )
        .unwrap();
        let _duplicate = apply(
            &Event::ReceiptRecorded(receipt.clone()),
            &manifest,
            &binding,
            &reserved,
            &mut files,
            &mut progress,
            6,
        )
        .unwrap_err();
        assert_eq!(progress.receipt.as_deref(), Some(receipt.as_str()));
        assert!(receipt.contains("published-durability-unconfirmed"));
        assert_eq!(receipt, expected_receipt(&manifest, &binding).unwrap());
    }
}
