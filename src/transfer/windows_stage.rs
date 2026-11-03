//! Handle-based directory enumeration for staging qualification.
//!
//! This does not create a stage, establish protected ancestry or ACLs, open
//! children without following reparse points, verify hard-link counts or
//! hashes, qualify a filesystem, or authorize publication. Callers must
//! establish those independent gates and use bounded blocking-I/O handling.

use super::manifest::valid_component;
use super::windows_lock::{FileIdentity, directory_identity};
use eyre::{Result, ensure};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::windows::io::AsRawHandle;
use windows::Win32::Foundation::{ERROR_NO_MORE_FILES, HANDLE};
use windows::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DEVICE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ID_BOTH_DIR_INFO, FileIdBothDirectoryInfo, FileIdBothDirectoryRestartInfo,
    GetFileInformationByHandleEx,
};

const MAX_ENTRIES: usize = 16;
const BUFFER_BYTES: usize = 64 * 1024;

/// A locally approved entry, bound to an independently checked file handle.
#[derive(Debug, Clone, Copy)]
pub struct ExpectedEntry<'a> {
    pub name: &'a str,
    pub identity: FileIdentity,
    pub size: u64,
}

fn check_batch(
    bytes: &[u8],
    expected: &BTreeMap<&str, ExpectedEntry<'_>>,
    seen: &mut BTreeSet<String>,
    observed: &mut usize,
) -> Result<()> {
    let mut offset = 0usize;
    loop {
        let header_size = std::mem::size_of::<FILE_ID_BOTH_DIR_INFO>();
        ensure!(
            offset
                .checked_add(header_size)
                .is_some_and(|end| end <= bytes.len()),
            "invalid directory record"
        );
        // SAFETY: The header is within the initialized allocation; unaligned
        // reads do not assume alignment of the OS-provided record.
        let record = unsafe {
            std::ptr::read_unaligned(bytes[offset..].as_ptr().cast::<FILE_ID_BOTH_DIR_INFO>())
        };
        *observed += 1;
        ensure!(
            *observed <= expected.len() + 2,
            "too many directory records"
        );
        let name_offset = offset + std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
        let name_len = usize::try_from(record.FileNameLength)?;
        ensure!(
            name_len > 0 && name_len % 2 == 0 && name_len <= 510,
            "invalid directory name length"
        );
        let end = name_offset
            .checked_add(name_len)
            .ok_or_else(|| eyre::eyre!("directory name overflow"))?;
        ensure!(end <= bytes.len(), "directory name outside buffer");
        if record.NextEntryOffset != 0 {
            let next = usize::try_from(record.NextEntryOffset)?;
            ensure!(
                offset
                    .checked_add(next)
                    .is_some_and(|record_end| end <= record_end),
                "overlapping directory records"
            );
        }
        let name_utf16: Vec<u16> = bytes[name_offset..end]
            .chunks_exact(2)
            .map(|part| u16::from_le_bytes([part[0], part[1]]))
            .collect();
        let name = String::from_utf16(&name_utf16)?;
        if name != "." && name != ".." {
            let entry = expected
                .get(name.as_str())
                .ok_or_else(|| eyre::eyre!("unexpected stage entry"))?;
            ensure!(seen.insert(name), "duplicate stage entry");
            ensure!(
                record.FileAttributes
                    & (FILE_ATTRIBUTE_DIRECTORY.0
                        | FILE_ATTRIBUTE_REPARSE_POINT.0
                        | FILE_ATTRIBUTE_DEVICE.0)
                    == 0,
                "unsafe stage entry attributes"
            );
            ensure!(
                u64::from_ne_bytes(record.FileId.to_ne_bytes()) == entry.identity.file_index,
                "stage entry identity mismatch"
            );
            ensure!(
                u64::try_from(record.EndOfFile)? == entry.size,
                "stage entry size mismatch"
            );
        }
        if record.NextEntryOffset == 0 {
            return Ok(());
        }
        let next = usize::try_from(record.NextEntryOffset)?;
        ensure!(
            next >= header_size && next % 8 == 0,
            "invalid next directory record"
        );
        offset = offset
            .checked_add(next)
            .ok_or_else(|| eyre::eyre!("directory record overflow"))?;
        ensure!(offset < bytes.len(), "directory record outside buffer");
    }
}

/// Compare an open directory's immediate entries with the approved set.
/// A match is only a directory-listing check, not a complete integrity or
/// publication guarantee. Call with a directory handle opened for enumeration.
/// Callers must serialize enumeration on this file object, including duplicate
/// handles, because the operating system maintains an enumeration cursor.
///
/// # Errors
/// Rejects unexpected names, attributes, sizes or IDs, malformed enumeration
/// data, unsafe directory identity, and unsupported filesystem operations.
pub fn verify_entries(
    directory: &File,
    expected_directory: FileIdentity,
    entries: &[ExpectedEntry<'_>],
) -> Result<()> {
    ensure!(
        (1..=MAX_ENTRIES).contains(&entries.len()),
        "invalid expected entry count"
    );
    ensure!(
        directory_identity(directory)? == expected_directory,
        "directory identity mismatch"
    );
    let mut expected = BTreeMap::new();
    let mut folded = BTreeSet::new();
    let mut identities = BTreeSet::new();
    for entry in entries {
        ensure!(valid_component(entry.name), "invalid expected component");
        ensure!(
            entry.identity.volume_serial == expected_directory.volume_serial,
            "entry volume mismatch"
        );
        ensure!(entry.identity.file_index != 0, "invalid expected identity");
        ensure!(
            folded.insert(entry.name.to_ascii_lowercase()),
            "duplicate expected component"
        );
        ensure!(
            identities.insert(entry.identity.file_index),
            "duplicate expected identity"
        );
        expected.insert(entry.name, *entry);
    }

    let mut seen = BTreeSet::new();
    let mut buffer = vec![0_u64; BUFFER_BYTES / std::mem::size_of::<u64>()];
    let mut restart = true;
    let mut observed = 0usize;
    loop {
        buffer.fill(0);
        let class = if restart {
            FileIdBothDirectoryRestartInfo
        } else {
            FileIdBothDirectoryInfo
        };
        restart = false;
        // SAFETY: The retained directory handle is live; the aligned buffer is
        // writable and exactly BUFFER_BYTES long for the duration of the call.
        let result = unsafe {
            GetFileInformationByHandleEx(
                HANDLE(directory.as_raw_handle()),
                class,
                buffer.as_mut_ptr().cast(),
                u32::try_from(BUFFER_BYTES)?,
            )
        };
        if let Err(error) = result {
            if error.code() == windows::core::HRESULT::from_win32(ERROR_NO_MORE_FILES.0) {
                break;
            }
            return Err(error.into());
        }
        let bytes = unsafe {
            // SAFETY: u64 and u8 have compatible validity, and the slice does
            // not outlive or mutate the initialized allocation.
            std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), BUFFER_BYTES)
        };
        check_batch(bytes, &expected, &mut seen, &mut observed)?;
    }
    ensure!(seen.len() == entries.len(), "approved stage entry missing");
    ensure!(
        directory_identity(directory)? == expected_directory,
        "directory identity changed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_directory_records_fail_closed() {
        let entry = ExpectedEntry {
            name: "one.bin",
            identity: FileIdentity {
                volume_serial: 1,
                file_index: 2,
            },
            size: 5,
        };
        let expected = BTreeMap::from([(entry.name, entry)]);
        let mut seen = BTreeSet::new();
        let mut observed = 0;
        let mut bytes = vec![0_u8; BUFFER_BYTES];
        assert!(check_batch(&bytes, &expected, &mut seen, &mut observed).is_err());

        let length = std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileNameLength);
        bytes[length..length + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        seen.clear();
        observed = 0;
        assert!(check_batch(&bytes, &expected, &mut seen, &mut observed).is_err());

        bytes[length..length + 4].copy_from_slice(&2_u32.to_le_bytes());
        let name = std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
        bytes[name..name + 2].copy_from_slice(&u16::from(b'x').to_le_bytes());
        let next = std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, NextEntryOffset);
        bytes[next..next + 4].copy_from_slice(&8_u32.to_le_bytes());
        seen.clear();
        observed = 0;
        assert!(check_batch(&bytes, &expected, &mut seen, &mut observed).is_err());
    }
}
