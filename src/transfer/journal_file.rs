//! Synchronous, bounded journal writes for an already-open synthetic file.
//!
//! This primitive is not an operational journal: the caller must establish
//! protected ancestry, ACLs, identity and cross-process ownership, and prove
//! filesystem ordering. This module is not wired to a receiver. An incomplete
//! write is preserved and recovery rejects it; it is never silently repaired.

use crate::transfer::journal::JournalBinding;
use crate::transfer::journal::JournalPhase;
use crate::transfer::journal::JournalRecord;
use crate::transfer::journal::decode_log;
use crate::transfer::journal::encode_frame;
use eyre::Result;
use eyre::ensure;
use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;

const MAX_LOG_BYTES: u64 = 1024 * 1024;

/// A preliminary pre-publication journal, holding an open file throughout.
/// It does not establish protected ownership or crash durability.
#[derive(Debug)]
pub struct JournalFile {
    file: File,
    binding: JournalBinding,
    last: JournalRecord,
    bytes: Vec<u8>,
    poisoned: bool,
}

fn read_bounded(file: &mut File) -> Result<Vec<u8>> {
    ensure!(
        file.metadata()?.len() <= MAX_LOG_BYTES,
        "journal exceeds size limit"
    );
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.take(MAX_LOG_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_LOG_BYTES,
        "journal exceeds size limit"
    );
    Ok(bytes)
}

impl JournalFile {
    /// Initialize an empty, already-open journal and sync its first frame.
    /// File creation, exclusive access and safe parent handling are external.
    ///
    /// # Errors
    /// Returns an error on expired approval, nonempty input, or write/sync failure.
    pub fn initialize(mut file: File, binding: &JournalBinding, now_unix: u64) -> Result<Self> {
        ensure!(read_bounded(&mut file)?.is_empty(), "journal is not empty");
        let last = JournalRecord::initial(binding);
        let bytes = encode_frame(&last)?;
        decode_log(&bytes, binding, now_unix)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(Self {
            file,
            binding: binding.clone(),
            last,
            bytes,
            poisoned: false,
        })
    }

    /// Reopen a complete unexpired journal without repairing or truncating it.
    ///
    /// # Errors
    /// Returns an error for malformed, incomplete, expired or conflicting input.
    pub fn reopen(mut file: File, binding: &JournalBinding, now_unix: u64) -> Result<Self> {
        let bytes = read_bounded(&mut file)?;
        let records = decode_log(&bytes, binding, now_unix)?;
        let last = records
            .last()
            .ok_or_else(|| eyre::eyre!("empty journal"))?
            .clone();
        ensure!(
            matches!(
                last.phase(),
                JournalPhase::Approved | JournalPhase::Receiving | JournalPhase::Aborted
            ),
            "journal contains publication states that require manual recovery"
        );
        Ok(Self {
            file,
            binding: binding.clone(),
            last,
            bytes,
            poisoned: false,
        })
    }

    #[must_use]
    pub fn phase(&self) -> JournalPhase {
        self.last.phase()
    }

    /// Append a pre-publication transition and sync the retained file handle.
    /// A failed write or sync poisons the instance, because its outcome may be
    /// uncertain. Publication states are disabled until their prerequisites exist.
    ///
    /// # Errors
    /// Returns an error on unsafe transition, expiration, mutation, size or I/O failure.
    pub fn advance(&mut self, next: JournalPhase, now_unix: u64) -> Result<()> {
        ensure!(!self.poisoned, "journal requires recovery");
        ensure!(
            matches!(next, JournalPhase::Receiving | JournalPhase::Aborted),
            "publication states are disabled"
        );
        let record = self.last.next(next)?;
        let frame = encode_frame(&record)?;
        ensure!(
            self.bytes
                .len()
                .checked_add(frame.len())
                .is_some_and(|n| n as u64 <= MAX_LOG_BYTES),
            "journal exceeds size limit"
        );
        // A subsequent I/O failure or unexpected mutation leaves the instance
        // unusable; recovery must inspect the complete file afresh.
        self.poisoned = true;
        let disk = read_bounded(&mut self.file)?;
        ensure!(disk == self.bytes, "journal changed while open");
        decode_log(&disk, &self.binding, now_unix)?;
        self.file.seek(SeekFrom::End(0))?;
        self.file.write_all(&frame)?;
        self.file.sync_all()?;
        self.bytes.extend(frame);
        self.last = record;
        self.poisoned = false;
        Ok(())
    }
}
