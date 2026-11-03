//! Preliminary Windows transaction journal for verified file observations.
//!
//! Records do not prove protected ancestry, safe staging, publication, or
//! power-loss durability. A commit-intent record is not permission to rename:
//! publication and receipt records remain disabled until their gates exist.

use super::blocking_io::BlockingIoGate;
use super::journal::JournalApproval;
use super::journal::JournalBinding;
use super::journal::ObjectIdentity;
use super::manifest::ApprovedManifest;
use super::manifest::parse_approved_manifest;
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
}

#[derive(Clone)]
struct FileEntry {
    observation: FileObservation,
    verified: bool,
}

#[derive(Clone, Facet, PartialEq, Eq)]
#[facet(deny_unknown_fields)]
struct Record {
    binding: JournalBinding,
    event: Event,
    sequence: u64,
    version: u32,
}

/// A retained exclusive journal handle and its validated pre-publication log.
/// File observations must be revalidated on each restart; they are not staging
/// access-control guarantees. No publication operation is exposed.
pub struct TransactionJournal {
    lock: ExclusiveFile,
    binding: JournalBinding,
    manifest: ApprovedManifest,
    stage_volume: u32,
    reserved: [ObjectIdentity; 3],
    records: Vec<u8>,
    sequence: u64,
    files: BTreeMap<String, FileEntry>,
    aborted: bool,
    commit_intent: Option<ObjectIdentity>,
    poisoned: bool,
}

impl std::fmt::Debug for TransactionJournal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransactionJournal")
            .field("sequence", &self.sequence)
            .field("file_count", &self.files.len())
            .field("aborted", &self.aborted)
            .field("has_commit_intent", &self.commit_intent.is_some())
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
    let actual = lock.identity();
    ensure!(
        actual.volume_serial == input.journal_file.volume_serial
            && actual.file_index == input.journal_file.file_index,
        "journal handle identity mismatch"
    );
    let binding = JournalBinding::from_approval(input)?;
    let manifest = parse_approved_manifest(
        input.manifest_bytes,
        input.manifest_sha256,
        input.transaction_id,
        input.now_unix,
    )?;
    Ok((binding, manifest))
}

fn apply(
    event: &Event,
    manifest: &ApprovedManifest,
    reserved: &[ObjectIdentity; 3],
    files: &mut BTreeMap<String, FileEntry>,
    aborted: &mut bool,
    commit_intent: &mut Option<ObjectIdentity>,
    sequence: u64,
) -> Result<()> {
    match event {
        Event::Approved => ensure!(
            sequence == 1 && files.is_empty() && !*aborted && commit_intent.is_none(),
            "invalid initial record"
        ),
        Event::FileClaimed(observation) | Event::FileVerified(observation) => {
            ensure!(
                sequence > 1 && !*aborted && commit_intent.is_none(),
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
                    && !*aborted
                    && commit_intent.is_none()
                    && *stage == reserved[1]
                    && files.len() == manifest.files().len()
                    && manifest
                        .files()
                        .all(|file| files.get(file.id()).is_some_and(|entry| entry.verified)),
                "invalid commit intent"
            );
            *commit_intent = Some(*stage);
        }
        Event::Aborted => {
            ensure!(
                sequence > 1 && !*aborted && commit_intent.is_none(),
                "invalid abort"
            );
            *aborted = true;
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
            aborted: false,
            commit_intent: None,
            poisoned: false,
        })
    }

    /// Replay a complete log against the exact local approval. Torn and expired
    /// logs fail closed and remain untouched for local inspection.
    ///
    /// # Errors
    /// Returns an error for an invalid binding, framing, sequence or transition.
    pub fn reopen(mut lock: ExclusiveFile, input: &JournalApproval<'_>) -> Result<Self> {
        let (binding, manifest) = approval(&lock, input)?;
        let bytes = read_log(&mut lock)?;
        ensure!(!bytes.is_empty(), "empty journal");
        let mut offset = 0usize;
        let mut sequence = 0u64;
        let mut files = BTreeMap::new();
        let mut aborted = false;
        let mut commit_intent = None;
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
                &[
                    input.destination_parent,
                    input.stage_directory,
                    input.journal_file,
                ],
                &mut files,
                &mut aborted,
                &mut commit_intent,
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
            aborted,
            commit_intent,
            poisoned: false,
        })
    }

    fn persist(&mut self, event: Event, now: u64) -> Result<()> {
        self.persist_with_clock(event, &|| Ok(now))
    }

    fn persist_with_clock(&mut self, event: Event, clock: &impl Fn() -> Result<u64>) -> Result<()> {
        ensure!(!self.poisoned && !self.aborted, "journal unavailable");
        ensure!(clock()? < self.manifest.expires_unix(), "approval expired");
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| eyre::eyre!("sequence overflow"))?;
        let mut files = self.files.clone();
        let mut aborted = self.aborted;
        let mut commit_intent = self.commit_intent;
        apply(
            &event,
            &self.manifest,
            &self.reserved,
            &mut files,
            &mut aborted,
            &mut commit_intent,
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
        self.aborted = aborted;
        self.commit_intent = commit_intent;
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
                && !self.aborted
                && self.commit_intent.is_none()
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
        ensure!(self.commit_intent.is_some(), "commit intent is missing");
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
                && !self.aborted
                && (allow_intent || self.commit_intent.is_none())
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

    /// The journaled pre-rename identity, if commit intent was recorded.
    /// This is not evidence that a rename took place.
    #[must_use]
    pub const fn commit_intent_stage(&self) -> Option<ObjectIdentity> {
        self.commit_intent
    }

    /// Compare a retained, non-reparse directory handle to the recorded
    /// pre-rename stage identity. A match alone does not prove containment,
    /// access control, exact contents, a rename, or permission for a receipt.
    ///
    /// # Errors
    /// Returns an error if commit intent is absent or the handle is unsafe.
    pub fn intent_matches_directory(&self, directory: &File) -> Result<bool> {
        let recorded = self
            .commit_intent
            .ok_or_else(|| eyre::eyre!("commit intent is missing"))?;
        let actual = directory_identity(directory)?;
        Ok(actual.volume_serial == recorded.volume_serial
            && actual.file_index == recorded.file_index)
    }

    /// Publication and receipt generation are deliberately unavailable.
    ///
    /// # Errors
    /// Always returns an error until the reviewed publication gates exist.
    pub fn commit(&self) -> Result<()> {
        bail!("publication is disabled")
    }
}
