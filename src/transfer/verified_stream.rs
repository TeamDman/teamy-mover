//! Bounded incremental integrity checks for one approved file body.
//!
//! This module does not create, publish, recover, or delete filesystem objects.
//! A verified stream is not proof of safe staging or crash durability.

use crate::transfer::manifest::ApprovedFile;
use eyre::Result;
use eyre::ensure;
use sha2::Digest;
use sha2::Sha256;
use std::io::Write;

/// The upper bound on an application chunk, independent of Vox framing.
pub const MAX_CHUNK_BYTES: usize = 16 * 1024;

/// Incrementally checks one body while writing it to a caller-provided sink.
#[derive(Debug)]
pub struct FileVerifier<W> {
    output: W,
    expected_bytes: u64,
    expected_sha256: String,
    seen: u64,
    hasher: Sha256,
    failed: bool,
}

impl<W: Write> FileVerifier<W> {
    #[must_use]
    pub fn new(file: ApprovedFile<'_>, output: W) -> Self {
        Self {
            output,
            expected_bytes: file.size(),
            expected_sha256: file.sha256().to_owned(),
            seen: 0,
            hasher: Sha256::new(),
            failed: false,
        }
    }

    /// Write a bounded chunk. An I/O or bounds failure permanently poisons
    /// this verifier; a partially written destination must never be published.
    ///
    /// # Errors
    /// Returns an error if the verifier failed, a limit is exceeded, or writing fails.
    pub fn push(&mut self, bytes: &[u8]) -> Result<()> {
        ensure!(!self.failed, "file verifier has failed");
        let chunk_size = u64::try_from(bytes.len())?;
        let Some(next) = self.seen.checked_add(chunk_size) else {
            self.failed = true;
            eyre::bail!("file body exceeds approved limits");
        };
        if bytes.len() > MAX_CHUNK_BYTES || next > self.expected_bytes {
            self.failed = true;
            eyre::bail!("file body exceeds approved limits");
        }
        if let Err(error) = self.output.write_all(bytes) {
            self.failed = true;
            return Err(error.into());
        }
        self.hasher.update(bytes);
        self.seen = next;
        Ok(())
    }

    /// Complete verification and flush the sink. This does not call `sync_all`
    /// or establish the identity or security of any on-disk file.
    ///
    /// # Errors
    /// Returns an error for a poisoned, incomplete, corrupt or unflushable body.
    pub fn finish(mut self) -> Result<W> {
        ensure!(!self.failed, "file verifier has failed");
        ensure!(self.seen == self.expected_bytes, "file body is incomplete");
        let actual = format!("{:x}", self.hasher.finalize());
        ensure!(
            actual == self.expected_sha256,
            "file digest does not match approval"
        );
        self.output.flush()?;
        Ok(self.output)
    }
}
