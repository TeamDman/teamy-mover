#![cfg(windows)]

use std::fs::{self, File, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;
use teamy_mover::transfer::windows_lock::{directory_identity, regular_file_identity};
use teamy_mover::transfer::windows_stage::{ExpectedEntry, verify_entries};
use windows::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
};

#[test]
fn retained_directory_enumeration_rejects_mismatches_and_extra_entries() {
    let fixture = tempfile::tempdir().unwrap();
    let directory_path = fixture.path().join("stage");
    fs::create_dir(&directory_path).unwrap();
    let first_path = directory_path.join("one.bin");
    let second_path = directory_path.join("two.bin");
    fs::write(&first_path, b"first").unwrap();
    fs::write(&second_path, b"second").unwrap();
    let first = regular_file_identity(&File::open(&first_path).unwrap()).unwrap();
    let second = regular_file_identity(&File::open(&second_path).unwrap()).unwrap();
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(&directory_path)
        .unwrap();
    let directory_id = directory_identity(&directory).unwrap();
    let entries = [
        ExpectedEntry {
            name: "one.bin",
            identity: first,
            size: 5,
        },
        ExpectedEntry {
            name: "two.bin",
            identity: second,
            size: 6,
        },
    ];
    verify_entries(&directory, directory_id, &entries).unwrap();
    verify_entries(&directory, directory_id, &entries).unwrap();

    let wrong_size = [
        ExpectedEntry {
            size: 4,
            ..entries[0]
        },
        entries[1],
    ];
    assert!(verify_entries(&directory, directory_id, &wrong_size).is_err());
    let mut different = first;
    different.file_index ^= 1 << 63;
    let wrong_id = [
        ExpectedEntry {
            identity: different,
            ..entries[0]
        },
        entries[1],
    ];
    assert!(verify_entries(&directory, directory_id, &wrong_id).is_err());
    assert!(verify_entries(&directory, directory_id, &entries[..1]).is_err());

    fs::write(directory_path.join("extra.bin"), b"extra").unwrap();
    assert!(verify_entries(&directory, directory_id, &entries).is_err());
    assert_eq!(fs::read(first_path).unwrap(), b"first");
    assert_eq!(fs::read(second_path).unwrap(), b"second");
}
