#![cfg(windows)]

//! Synthetic Windows sharing probes only. These use the current process token
//! and ordinary temporary directories; they do not qualify a Downloads path,
//! assess another account's effective access, or authorize publication.

use std::fs::File;
use std::fs::OpenOptions;
use std::os::windows::fs::OpenOptionsExt;
use std::path::Path;
use windows::Win32::Foundation::ERROR_SHARING_VIOLATION;
use windows::Win32::Storage::FileSystem::DELETE;
use windows::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;
use windows::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
use windows::Win32::Storage::FileSystem::FILE_LIST_DIRECTORY;
use windows::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES;
use windows::Win32::Storage::FileSystem::FILE_SHARE_DELETE;
use windows::Win32::Storage::FileSystem::FILE_SHARE_READ;
use windows::Win32::Storage::FileSystem::FILE_SHARE_WRITE;

fn open_directory(path: &Path, desired: u32, shares: u32) -> std::io::Result<File> {
    OpenOptions::new()
        .access_mode(desired)
        .share_mode(shares)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
}

#[test]
fn attributes_only_handle_does_not_provide_the_delete_guard() {
    let root = tempfile::tempdir().unwrap();
    let original = root.path().join("original");
    let renamed = root.path().join("renamed");
    std::fs::create_dir(&original).unwrap();
    let metadata_only = open_directory(
        &original,
        FILE_READ_ATTRIBUTES.0,
        (FILE_SHARE_READ | FILE_SHARE_WRITE).0,
    )
    .unwrap();
    // A metadata-only open did not protect this synthetic directory in the
    // observed environment. Do not use it as an ancestry guard.
    std::fs::rename(&original, &renamed).unwrap();
    drop(metadata_only);
    assert!(renamed.is_dir());
}

#[test]
fn no_delete_share_blocks_directory_rename_until_handle_closes() {
    let root = tempfile::tempdir().unwrap();
    let original = root.path().join("original");
    let renamed = root.path().join("renamed");
    std::fs::create_dir(&original).unwrap();
    let guard = open_directory(
        &original,
        (FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES).0,
        (FILE_SHARE_READ | FILE_SHARE_WRITE).0,
    )
    .unwrap();
    assert!(std::fs::rename(&original, &renamed).is_err());
    assert!(original.is_dir());
    assert!(!renamed.exists());
    drop(guard);
    std::fs::rename(&original, &renamed).unwrap();
    assert!(renamed.is_dir());
}

#[test]
fn preopened_delete_handle_conflicts_with_no_delete_share_guard() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("existing");
    std::fs::create_dir(&directory).unwrap();
    let preexisting = open_directory(
        &directory,
        (DELETE | FILE_READ_ATTRIBUTES).0,
        (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0,
    )
    .unwrap();
    let guard = open_directory(
        &directory,
        (FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES).0,
        (FILE_SHARE_READ | FILE_SHARE_WRITE).0,
    );
    let error = guard.expect_err("an existing DELETE handle must block the guard");
    assert_eq!(
        error.raw_os_error(),
        Some(i32::try_from(ERROR_SHARING_VIOLATION.0).unwrap())
    );
    drop(preexisting);
    let guard = open_directory(
        &directory,
        (FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES).0,
        (FILE_SHARE_READ | FILE_SHARE_WRITE).0,
    )
    .unwrap();
    drop(guard);
    assert!(directory.is_dir());
}
