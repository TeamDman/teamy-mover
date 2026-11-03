//! Gated Windows handle-relative no-replace rename primitive.
//!
//! No operational constructor exists for `PublicationPermit`: protected
//! ancestry, exact-set verification, effective access, recovery and lifetime
//! gates still require implementation and independent review. This module
//! does not itself qualify a filesystem, create receipts, or delete sources.

use super::manifest::valid_component;
use super::transaction_journal::TransactionJournal;
use super::windows_acl::CreatedDirectory;
use eyre::{Result, ensure};
use std::fs::File;
use std::os::windows::io::AsRawHandle;
use windows::Wdk::Storage::FileSystem::{
    FILE_RENAME_INFORMATION, FILE_RENAME_INFORMATION_0, FileRenameInformation, NtSetInformationFile,
};
use windows::Win32::Foundation::{HANDLE, STATUS_PENDING};
use windows::Win32::System::IO::IO_STATUS_BLOCK;

/// Reserved for a future, independently reviewed publication gate.
/// No operational constructor is provided.
#[derive(Debug)]
pub struct PublicationPermit(());

/// An observed rename outcome, never a durability or receipt guarantee.
#[derive(Debug, PartialEq, Eq)]
pub enum RenameOutcome {
    /// Windows reported success; directory and journal durability are unconfirmed.
    RenamedDurabilityUnconfirmed,
    /// Outcome must be reconciled locally; do not retry or issue a receipt.
    Unconfirmed { status: u32 },
}

#[cfg(test)]
pub(crate) fn synthetic_permit() -> PublicationPermit {
    PublicationPermit(())
}

/// Attempt one approved no-replace rename while retaining the journal, stage
/// and destination-parent handles. The caller must run this blocking operation
/// under an appropriate deadline and preserve all objects after uncertainty.
/// The private permit must eventually encode the reviewed filesystem, ancestry,
/// file verification, sharing, token, lock and recovery qualifications.
///
/// # Errors
/// Returns an error before the rename if the name or journal binding is invalid.
pub fn rename_with_permit(
    _permit: PublicationPermit,
    journal: &mut TransactionJournal,
    stage: &mut CreatedDirectory,
    destination_parent: &File,
    final_name: &str,
) -> Result<RenameOutcome> {
    ensure!(
        valid_component(final_name),
        "invalid final directory component"
    );
    journal.check_publication_binding(destination_parent, stage, final_name)?;
    let name: Vec<u16> = final_name.encode_utf16().collect();
    let bytes = name
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .ok_or_else(|| eyre::eyre!("directory component too large"))?;
    let offset = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName);
    let size = std::mem::size_of::<FILE_RENAME_INFORMATION>()
        .checked_add(bytes)
        .ok_or_else(|| eyre::eyre!("rename buffer too large"))?;
    let mut buffer = vec![0_u64; size.div_ceil(std::mem::size_of::<u64>())];
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    let header = FILE_RENAME_INFORMATION {
        Anonymous: FILE_RENAME_INFORMATION_0 {
            ReplaceIfExists: false,
        },
        RootDirectory: HANDLE(destination_parent.as_raw_handle()),
        FileNameLength: u32::try_from(bytes)?,
        FileName: [0],
    };
    // SAFETY: the u64-backed allocation is aligned and contains the header.
    unsafe { info.write(header) };
    ensure!(
        offset.is_multiple_of(std::mem::size_of::<u16>()),
        "invalid rename layout"
    );
    let target = buffer
        .as_mut_ptr()
        .cast::<u16>()
        .wrapping_add(offset / std::mem::size_of::<u16>());
    // SAFETY: the allocation contains the UTF-16 tail; the source is separate.
    unsafe { std::ptr::copy_nonoverlapping(name.as_ptr(), target, name.len()) };
    let mut io_status = Box::new(IO_STATUS_BLOCK::default());
    journal.check_publication_time()?;
    // SAFETY: CreatedDirectory can only originate from our synchronous
    // NtCreateFile call. Both retained handles and initialized, aligned buffers
    // stay live during this call; the final name is a simple component.
    let status = unsafe {
        NtSetInformationFile(
            HANDLE(stage.as_raw_handle()),
            &raw mut *io_status,
            info.cast(),
            u32::try_from(size)?,
            FileRenameInformation,
        )
    };
    if status == STATUS_PENDING {
        // A synchronous handle should not return pending. If it ever does,
        // retain the I/O buffers indefinitely: freeing them could race a late
        // kernel completion. The consumed permit limits this to one attempt.
        std::mem::forget(buffer);
        std::mem::forget(io_status);
    }
    if status.0 == 0 {
        Ok(RenameOutcome::RenamedDurabilityUnconfirmed)
    } else {
        Ok(RenameOutcome::Unconfirmed {
            status: u32::from_ne_bytes(status.0.to_ne_bytes()),
        })
    }
}
