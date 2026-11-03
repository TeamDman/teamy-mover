//! Handle-based named-stream checks for a future qualified Windows transfer.
//!
//! This does not qualify a volume, secure ancestry, exclude concurrent writers,
//! establish complete crash recovery, or authorize staging or publication.
//! Callers must hold suitably secured handles and run filesystem work through
//! the transaction's bounded blocking-I/O gate.

use super::windows_lock::FileIdentity;
use super::windows_lock::directory_identity;
use super::windows_lock::regular_file_identity;
use eyre::Result;
use eyre::ensure;
use std::fs::File;
use std::os::windows::io::AsRawHandle;
use windows::Win32::Foundation::ERROR_HANDLE_EOF;
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Foundation::SetLastError;
use windows::Win32::Storage::FileSystem::FILE_STREAM_INFO;
use windows::Win32::Storage::FileSystem::FileStreamInfo;
use windows::Win32::Storage::FileSystem::GetFileInformationByHandleEx;

// A too-small buffer or unsupported query fails closed; no partial result is
// accepted. The buffer and query must be reviewed against the qualified NTFS.
const BUFFER_BYTES: usize = 64 * 1024;
const UNNAMED_DATA_UTF16: &[u8] = b":\0:\0$\0D\0A\0T\0A\0";

enum StreamResult {
    None,
    OneUnnamedData(u64),
}

fn parse_only_unnamed_stream(bytes: &[u8]) -> Result<StreamResult> {
    let name_offset = std::mem::offset_of!(FILE_STREAM_INFO, StreamName);
    ensure!(bytes.len() >= name_offset, "truncated stream record");
    let next = u32::from_le_bytes(bytes[0..4].try_into()?);
    let name_len = usize::try_from(u32::from_le_bytes(bytes[4..8].try_into()?))?;
    let stream_size = i64::from_le_bytes(bytes[8..16].try_into()?);
    ensure!(next == 0, "more than one stream is not approved");
    ensure!(
        name_len == UNNAMED_DATA_UTF16.len()
            && name_offset
                .checked_add(name_len)
                .is_some_and(|end| end <= bytes.len()),
        "invalid or unapproved stream name"
    );
    ensure!(
        &bytes[name_offset..name_offset + name_len] == UNNAMED_DATA_UTF16,
        "named stream is not approved"
    );
    Ok(StreamResult::OneUnnamedData(u64::try_from(stream_size)?))
}

fn query_streams(file: &File) -> Result<StreamResult> {
    // u64 storage meets FILE_STREAM_INFO's documented eight-byte alignment.
    let mut buffer = vec![0_u64; BUFFER_BYTES / std::mem::size_of::<u64>()];
    // SAFETY: last-error state is thread-local; no await occurs during query.
    unsafe { SetLastError(ERROR_SUCCESS) };
    // SAFETY: the file handle remains live and the aligned buffer is writable
    // for exactly BUFFER_BYTES for the duration of this synchronous call.
    let result = unsafe {
        GetFileInformationByHandleEx(
            HANDLE(file.as_raw_handle()),
            FileStreamInfo,
            buffer.as_mut_ptr().cast(),
            u32::try_from(BUFFER_BYTES)?,
        )
    };
    // SAFETY: GetLastError reads this thread's last-error value immediately.
    let last_error = unsafe { GetLastError() };
    let empty_buffer = || buffer.iter().all(|word| *word == 0);
    match result {
        Ok(()) if last_error == ERROR_HANDLE_EOF && empty_buffer() => Ok(StreamResult::None),
        Ok(()) => {
            // SAFETY: u64 storage is initialized and the byte view does not
            // outlive or mutate that storage.
            let bytes = unsafe {
                std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), BUFFER_BYTES)
            };
            parse_only_unnamed_stream(bytes)
        }
        Err(error)
            if error.code() == windows::core::HRESULT::from_win32(ERROR_HANDLE_EOF.0)
                && empty_buffer() =>
        {
            Ok(StreamResult::None)
        }
        Err(error) => Err(error.into()),
    }
}

/// Check an already-open regular file has only its approved unnamed data stream.
/// The caller must independently hold safe ancestry and exclude writers.
///
/// # Errors
/// Rejects changed identity, unsafe file type/link count, unexpected streams,
/// inconsistent size, malformed records, and failed or unsupported queries.
pub fn verify_file_streams(file: &File, expected: FileIdentity, size: u64) -> Result<()> {
    ensure!(regular_file_identity(file)? == expected, "file identity changed");
    match query_streams(file)? {
        StreamResult::OneUnnamedData(actual) => ensure!(actual == size, "stream size mismatch"),
        StreamResult::None => eyre::bail!("missing unnamed file stream"),
    }
    ensure!(regular_file_identity(file)? == expected, "file identity changed");
    Ok(())
}

/// Check an already-open directory has no data streams. The caller must
/// independently verify the path, qualified filesystem and sharing boundary.
///
/// # Errors
/// Rejects changed identity, unexpected data streams, malformed records, and
/// failed or unsupported queries.
pub fn verify_directory_streams(directory: &File, expected: FileIdentity) -> Result<()> {
    ensure!(directory_identity(directory)? == expected, "directory identity changed");
    ensure!(matches!(query_streams(directory)?, StreamResult::None), "directory data stream is not approved");
    ensure!(directory_identity(directory)? == expected, "directory identity changed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_or_multiple_stream_records_fail_closed() {
        let mut bytes = vec![0_u8; 128];
        let name_offset = std::mem::offset_of!(FILE_STREAM_INFO, StreamName);
        bytes[4..8].copy_from_slice(&u32::try_from(UNNAMED_DATA_UTF16.len()).unwrap().to_le_bytes());
        bytes[name_offset..name_offset + UNNAMED_DATA_UTF16.len()].copy_from_slice(UNNAMED_DATA_UTF16);
        assert!(matches!(parse_only_unnamed_stream(&bytes), Ok(StreamResult::OneUnnamedData(0))));
        bytes[0..4].copy_from_slice(&32_u32.to_le_bytes());
        let _multiple = parse_only_unnamed_stream(&bytes).err().unwrap();
        bytes[0..4].fill(0);
        bytes[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        let _malformed = parse_only_unnamed_stream(&bytes).err().unwrap();
        let _truncated = parse_only_unnamed_stream(&bytes[..8]).err().unwrap();
    }
}
