//! Windows exclusive-file primitive for the transfer journal.
//!
//! This module does not establish that a parent path or ACL is trustworthy and
//! must not be used by a receiver until those separate gates are implemented.
//! It never creates, writes, renames, or deletes a file.

use eyre::Result;
use eyre::ensure;
use std::fs::File;
use std::fs::OpenOptions;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION;
use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_DIRECTORY;
use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
use windows::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
use windows::Win32::Storage::FileSystem::GetFileInformationByHandle;

/// Stable identity returned by Windows for an already-open file handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileIdentity {
    pub volume_serial: u32,
    pub file_index: u64,
}

/// An open file whose sharing mode prevents competing opens while held.
#[derive(Debug)]
pub struct ExclusiveFile {
    file: File,
    identity: FileIdentity,
}

/// Read identity from an already-open regular file and reject hard links and
/// reparse points. This does not establish trust in its ancestors or ACL.
///
/// # Errors
/// Returns an error for unsupported handles or unsafe file metadata.
pub fn regular_file_identity(file: &File) -> Result<FileIdentity> {
    ensure!(
        file.metadata()?.is_file(),
        "journal handle is not a regular file"
    );
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `file` owns a live Windows handle for the duration of the call,
    // and `info` points to a properly initialized, writable output structure.
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &raw mut info)? };
    ensure!(
        info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT.0 | FILE_ATTRIBUTE_DIRECTORY.0) == 0,
        "journal must be a non-reparse regular file"
    );
    ensure!(info.nNumberOfLinks == 1, "journal must not have hard links");
    let file_index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
    ensure!(
        file_index != 0,
        "filesystem did not provide a usable file identity"
    );
    Ok(FileIdentity {
        volume_serial: info.dwVolumeSerialNumber,
        file_index,
    })
}

/// Read a retained directory handle's identity and reject a reparse point.
/// This does not establish safe ancestry, ACLs, or permission to publish.
///
/// # Errors
/// Returns an error if the handle is not a non-reparse directory with an ID.
pub fn directory_identity(file: &File) -> Result<FileIdentity> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `file` owns a live Windows handle and `info` is writable.
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &raw mut info)? };
    ensure!(
        info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0
            && info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 == 0,
        "handle must be a non-reparse directory"
    );
    let file_index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
    ensure!(
        file_index != 0,
        "filesystem did not provide a usable directory identity"
    );
    Ok(FileIdentity {
        volume_serial: info.dwVolumeSerialNumber,
        file_index,
    })
}

impl ExclusiveFile {
    /// Wrap an owned handle. The caller must have opened it with share
    /// mode zero and must not have duplicated or exposed the handle.
    pub(crate) fn from_opened_no_share(file: File) -> Result<Self> {
        let identity = regular_file_identity(&file)?;
        Ok(Self { file, identity })
    }

    pub(crate) fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    pub(crate) const fn identity(&self) -> FileIdentity {
        self.identity
    }

    /// Open an existing approved file without sharing and bind it to its
    /// expected volume/file identity. The file is never created by this call.
    /// The caller must independently secure and identity-check every ancestor,
    /// ACL and transaction binding before relying on this as a journal lock.
    ///
    /// # Errors
    /// Returns an error if the file is unavailable, unsafe, or not the approved file.
    pub fn acquire(path: &Path, expected: FileIdentity) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(path)?;
        let identity = regular_file_identity(&file)?;
        ensure!(
            identity == expected,
            "journal identity does not match approval"
        );
        Ok(Self { file, identity })
    }

    /// Recheck the identity of the retained exclusive handle.
    ///
    /// # Errors
    /// Returns an error if identity or file safety attributes changed.
    pub fn verify(&self) -> Result<()> {
        ensure!(
            regular_file_identity(&self.file)? == self.identity,
            "journal identity changed"
        );
        Ok(())
    }
}
