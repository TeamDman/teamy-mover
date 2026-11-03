//! In-memory sequencing of approved file-body verification.
//!
//! This is not a receiver, journal, staging implementation, publication
//! authorization, or proof that a previously returned sink remains unchanged.

use crate::transfer::manifest::ApprovedManifest;
use crate::transfer::verified_stream::FileVerifier;
use eyre::Result;
use eyre::bail;
use eyre::ensure;
use std::collections::HashSet;
use std::fmt;
use std::io::Write;

struct Active<W> {
    id: String,
    verifier: FileVerifier<W>,
}

/// Tracks one at-a-time bodies from an already approved manifest.
///
/// Callers must supply a trusted current UTC time at every checkpoint and
/// separately enforce a monotonic connection/session deadline. A protocol or
/// I/O error poisons this in-memory session; retry and recovery require separate,
/// authorized journal and staging logic.
pub struct BodySetVerifier<W> {
    manifest: ApprovedManifest,
    completed: HashSet<String>,
    active: Option<Active<W>>,
    failed: bool,
}

impl<W> fmt::Debug for BodySetVerifier<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BodySetVerifier")
            .field("completed_count", &self.completed.len())
            .field("has_active_body", &self.active.is_some())
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl<W: Write> BodySetVerifier<W> {
    /// Start a verifier for an approved, unexpired manifest.
    ///
    /// # Errors
    /// Returns an error if the approval has expired.
    pub fn new(manifest: ApprovedManifest, now_unix: u64) -> Result<Self> {
        ensure!(manifest.expires_unix() > now_unix, "manifest has expired");
        Ok(Self {
            manifest,
            completed: HashSet::new(),
            active: None,
            failed: false,
        })
    }

    fn checkpoint(&mut self, now_unix: u64) -> Result<()> {
        ensure!(!self.failed, "body session has failed");
        if now_unix >= self.manifest.expires_unix() {
            self.failed = true;
            self.active.take();
            bail!("manifest has expired");
        }
        Ok(())
    }

    /// Begin exactly one approved file ID. The caller owns safe sink creation.
    ///
    /// # Errors
    /// Returns an error for expiry, invalid or duplicate IDs, or overlapping bodies.
    pub fn begin(&mut self, id: &str, output: W, now_unix: u64) -> Result<()> {
        self.checkpoint(now_unix)?;
        if self.active.is_some() || self.completed.contains(id) {
            self.failed = true;
            self.active.take();
            bail!("overlapping or duplicate file body");
        }
        let Some(file) = self.manifest.files().find(|file| file.id() == id) else {
            self.failed = true;
            bail!("file ID is not approved");
        };
        self.active = Some(Active {
            id: id.to_owned(),
            verifier: FileVerifier::new(file, output),
        });
        Ok(())
    }

    /// Feed one bounded chunk to the active body.
    ///
    /// # Errors
    /// Returns an error for expiry, missing body, size limits, or sink failure.
    pub fn push(&mut self, bytes: &[u8], now_unix: u64) -> Result<()> {
        self.checkpoint(now_unix)?;
        let Some(active) = self.active.as_mut() else {
            self.failed = true;
            bail!("no active file body");
        };
        if let Err(error) = active.verifier.push(bytes) {
            self.failed = true;
            self.active.take();
            return Err(error);
        }
        Ok(())
    }

    /// Verify and flush the active body, returning its sink to the caller.
    ///
    /// # Errors
    /// Returns an error for expiry, missing body, mismatch, or sink failure.
    pub fn finish(&mut self, now_unix: u64) -> Result<W> {
        self.checkpoint(now_unix)?;
        let Some(active) = self.active.take() else {
            self.failed = true;
            bail!("no active file body");
        };
        match active.verifier.finish() {
            Ok(output) => {
                self.completed.insert(active.id);
                Ok(output)
            }
            Err(error) => {
                self.failed = true;
                Err(error)
            }
        }
    }

    /// Indicates only whether each approved byte stream passed its check.
    /// This is not evidence of protected staging or permission to publish.
    #[must_use]
    pub fn all_bodies_checked(&mut self, now_unix: u64) -> bool {
        self.checkpoint(now_unix).is_ok()
            && self.active.is_none()
            && self.completed.len() == self.manifest.files().len()
    }
}
