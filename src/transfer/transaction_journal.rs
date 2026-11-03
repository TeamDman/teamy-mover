//! Preliminary Windows transaction journal for verified file observations.
//!
//! This is not connected to a receiver. Its records do not prove protected
//! ancestry, safe staging, publication, or power-loss durability. Commit and
//! receipt records remain disabled. A trusted caller must separately establish
//! ACLs, containment and the reviewed local threat boundary.

use super::journal::JournalApproval;
use super::journal::JournalBinding;
use super::journal::ObjectIdentity;
use super::manifest::ApprovedManifest;
use super::manifest::parse_approved_manifest;
use super::verified_stream::FileVerifier;
use super::windows_lock::ExclusiveFile;
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
    FileVerified(FileObservation),
    Aborted,
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
    files: BTreeMap<String, FileObservation>,
    aborted: bool,
    poisoned: bool,
}

impl std::fmt::Debug for TransactionJournal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransactionJournal")
            .field("sequence", &self.sequence)
            .field("file_count", &self.files.len())
            .field("aborted", &self.aborted)
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
    stage_volume: u32,
    reserved: &[ObjectIdentity; 3],
    files: &mut BTreeMap<String, FileObservation>,
    aborted: &mut bool,
    sequence: u64,
) -> Result<()> {
    match event {
        Event::Approved => ensure!(
            sequence == 1 && files.is_empty() && !*aborted,
            "invalid initial record"
        ),
        Event::FileVerified(observation) => {
            ensure!(sequence > 1 && !*aborted, "invalid file record");
            let file = manifest
                .files()
                .find(|f| f.id() == observation.id)
                .ok_or_else(|| eyre::eyre!("file not in manifest"))?;
            ensure!(
                observation.size == file.size()
                    && observation.sha256 == file.sha256()
                    && observation.object.volume_serial == stage_volume
                    && observation.object.file_index != 0
                    && !reserved.contains(&observation.object),
                "file observation mismatch"
            );
            ensure!(
                !files.contains_key(&observation.id)
                    && !files.values().any(|f| f.object == observation.object),
                "duplicate file or identity"
            );
            files.insert(observation.id.clone(), observation.clone());
        }
        Event::Aborted => {
            ensure!(sequence > 1 && !*aborted, "invalid abort");
            *aborted = true;
        }
    }
    Ok(())
}

impl TransactionJournal {
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
                input.stage_directory.volume_serial,
                &[
                    input.destination_parent,
                    input.stage_directory,
                    input.journal_file,
                ],
                &mut files,
                &mut aborted,
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
            poisoned: false,
        })
    }

    fn persist(&mut self, event: Event, now: u64) -> Result<()> {
        ensure!(!self.poisoned && !self.aborted, "journal unavailable");
        ensure!(now < self.manifest.expires_unix(), "approval expired");
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| eyre::eyre!("sequence overflow"))?;
        let mut files = self.files.clone();
        let mut aborted = self.aborted;
        apply(
            &event,
            &self.manifest,
            self.stage_volume,
            &self.reserved,
            &mut files,
            &mut aborted,
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
        append(&mut self.lock, &frame)?;
        self.records.extend(frame);
        self.files = files;
        self.aborted = aborted;
        self.sequence = sequence;
        self.poisoned = false;
        Ok(())
    }

    /// Verify a retained file handle's identity, exact length and digest, sync
    /// it, then record its observed identity. A repeat succeeds only for the
    /// same identity after re-verification. This does not establish containment.
    ///
    /// # Errors
    /// Returns an error on mismatch, expiry, invalid identity or I/O failure.
    pub fn verify_file(&mut self, id: &str, file: &mut File, now: u64) -> Result<()> {
        ensure!(
            !self.poisoned && !self.aborted && now < self.manifest.expires_unix(),
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
            ensure!(*existing == observation, "conflicting file identity");
        }
        file.seek(SeekFrom::Start(0))?;
        let mut verifier = FileVerifier::new(approved, std::io::sink());
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            verifier.push(&buf[..n])?;
        }
        verifier.finish()?;
        file.sync_all()?;
        ensure!(identity(file)? == object, "file identity changed");
        if self.files.contains_key(id) {
            return Ok(());
        }
        self.persist(Event::FileVerified(observation), now)
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
        self.files.contains_key(id)
    }

    /// Publication and receipt generation are deliberately unavailable.
    ///
    /// # Errors
    /// Always returns an error until the reviewed publication gates exist.
    pub fn commit(&self) -> Result<()> {
        bail!("publication is disabled")
    }
}
