#![cfg(windows)]

//! Synthetic data-stream probes. These do not qualify any real directory or
//! establish race-free publication or recovery.

use std::fs::File;
use std::fs::OpenOptions;
use std::os::windows::fs::OpenOptionsExt;
use std::path::Path;
use std::path::PathBuf;
use teamy_mover::transfer::windows_lock::directory_identity;
use teamy_mover::transfer::windows_lock::regular_file_identity;
use teamy_mover::transfer::windows_streams::verify_directory_streams;
use teamy_mover::transfer::windows_streams::verify_file_streams;
use windows::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;
use windows::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
use windows::Win32::Storage::FileSystem::FILE_LIST_DIRECTORY;
use windows::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES;
use windows::Win32::Storage::FileSystem::FILE_SHARE_DELETE;
use windows::Win32::Storage::FileSystem::FILE_SHARE_READ;
use windows::Win32::Storage::FileSystem::FILE_SHARE_WRITE;

fn named_stream(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(":unexpected");
    PathBuf::from(name)
}

fn open_directory(path: &Path) -> File {
    OpenOptions::new()
        .access_mode((FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES).0)
        .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
        .unwrap()
}

#[test]
fn approved_file_rejects_empty_and_nonempty_named_streams() {
    for content in [b"".as_slice(), b"hidden".as_slice()] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("fixture.bin");
        std::fs::write(&path, b"synthetic").unwrap();
        let file = File::open(&path).unwrap();
        let identity = regular_file_identity(&file).unwrap();
        verify_file_streams(&file, identity, 9).unwrap();
        std::fs::write(named_stream(&path), content).unwrap();
        let _rejected = verify_file_streams(&file, identity, 9).unwrap_err();
        assert_eq!(std::fs::read(&path).unwrap(), b"synthetic");
    }
}

#[test]
fn directory_rejects_named_data_stream() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("stage");
    std::fs::create_dir(&path).unwrap();
    let directory = open_directory(&path);
    let identity = directory_identity(&directory).unwrap();
    verify_directory_streams(&directory, identity).unwrap();
    std::fs::write(named_stream(&path), b"hidden").unwrap();
    let _rejected = verify_directory_streams(&directory, identity).unwrap_err();
    assert!(path.is_dir());
}
