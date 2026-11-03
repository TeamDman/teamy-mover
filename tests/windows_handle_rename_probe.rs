#![cfg(windows)]
//! Opt-in synthetic probe, not a production publication implementation.

use sha2::{Digest, Sha256};
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::path::PathBuf;
use teamy_mover::transfer::journal::{JournalApproval, ObjectIdentity};
use teamy_mover::transfer::transaction_journal::TransactionJournal;
use teamy_mover::transfer::windows_lock::directory_identity;
use teamy_mover::transfer::windows_lock::{ExclusiveFile, regular_file_identity};
use teamy_mover::transfer::windows_stage::{ExpectedEntry, verify_entries};
use windows::Wdk::Storage::FileSystem::FILE_RENAME_INFORMATION;
use windows::Wdk::Storage::FileSystem::FILE_RENAME_INFORMATION_0;
use windows::Wdk::Storage::FileSystem::FileRenameInformation;
use windows::Wdk::Storage::FileSystem::NtSetInformationFile;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Foundation::NTSTATUS;
use windows::Win32::Foundation::STATUS_OBJECT_NAME_COLLISION;
use windows::Win32::Storage::FileSystem::DELETE;
use windows::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;
use windows::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
use windows::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES;
use windows::Win32::Storage::FileSystem::FILE_RENAME_INFO;
use windows::Win32::Storage::FileSystem::FILE_RENAME_INFO_0;
use windows::Win32::Storage::FileSystem::FILE_SHARE_DELETE;
use windows::Win32::Storage::FileSystem::FILE_SHARE_READ;
use windows::Win32::Storage::FileSystem::FILE_SHARE_WRITE;
use windows::Win32::Storage::FileSystem::FileRenameInfo;
use windows::Win32::Storage::FileSystem::SetFileInformationByHandle;
use windows::Win32::System::IO::IO_STATUS_BLOCK;

fn fixture_base() -> PathBuf {
    if std::env::var_os("TEAMY_WINDOWS_TEST_VOLUME").as_deref()
        == Some(std::ffi::OsStr::new("system-temp"))
    {
        std::env::temp_dir().join("teamy-mover-rename-test-fixtures")
    } else {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("rename-test-fixtures")
    }
}

fn open_directory(path: &Path, can_rename: bool) -> std::io::Result<File> {
    let access = FILE_READ_ATTRIBUTES.0 | if can_rename { DELETE.0 } else { 0 };
    OpenOptions::new()
        .access_mode(access)
        .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
}

fn rename_relative(source: &File, parent: &File, name: &str) -> windows::core::Result<()> {
    let name: Vec<u16> = name.encode_utf16().collect();
    let offset = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    let byte_len = name.len() * std::mem::size_of::<u16>();
    let size = (offset + byte_len).max(std::mem::size_of::<FILE_RENAME_INFO>());
    let mut buffer = vec![0_u64; size.div_ceil(std::mem::size_of::<u64>())];
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    let header = FILE_RENAME_INFO {
        Anonymous: FILE_RENAME_INFO_0 {
            ReplaceIfExists: false,
        },
        RootDirectory: HANDLE(parent.as_raw_handle()),
        FileNameLength: u32::try_from(byte_len).unwrap(),
        FileName: [0],
    };
    // SAFETY: The u64-backed buffer is aligned and at least the header size.
    unsafe { info.write(header) };
    assert!(offset.is_multiple_of(std::mem::size_of::<u16>()));
    let filename = buffer
        .as_mut_ptr()
        .cast::<u16>()
        .wrapping_add(offset / std::mem::size_of::<u16>());
    // SAFETY: The buffer includes the entire UTF-16 filename tail; the
    // separate source vector does not overlap the destination allocation.
    unsafe { std::ptr::copy_nonoverlapping(name.as_ptr(), filename, name.len()) };
    // SAFETY: Both fixture-owned handles and the initialized buffer remain
    // live for the duration of this call, and the size fits the buffer.
    unsafe {
        SetFileInformationByHandle(
            HANDLE(source.as_raw_handle()),
            FileRenameInfo,
            info.cast(),
            u32::try_from(size).unwrap(),
        )
    }
}

fn nt_rename_relative(source: &File, parent: &File, name: &str) -> NTSTATUS {
    let name: Vec<u16> = name.encode_utf16().collect();
    let offset = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName);
    let byte_len = name.len() * std::mem::size_of::<u16>();
    let size = (offset + byte_len).max(std::mem::size_of::<FILE_RENAME_INFORMATION>());
    let mut buffer = vec![0_u64; size.div_ceil(std::mem::size_of::<u64>())];
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    let mut io_status = IO_STATUS_BLOCK::default();
    let header = FILE_RENAME_INFORMATION {
        Anonymous: FILE_RENAME_INFORMATION_0 {
            ReplaceIfExists: false,
        },
        RootDirectory: HANDLE(parent.as_raw_handle()),
        FileNameLength: u32::try_from(byte_len).unwrap(),
        FileName: [0],
    };
    // SAFETY: The u64-backed buffer is aligned and at least the header size.
    unsafe { info.write(header) };
    assert!(offset.is_multiple_of(std::mem::size_of::<u16>()));
    let filename = buffer
        .as_mut_ptr()
        .cast::<u16>()
        .wrapping_add(offset / std::mem::size_of::<u16>());
    // SAFETY: The buffer includes the entire UTF-16 filename tail; the
    // separate source vector does not overlap the destination allocation.
    unsafe { std::ptr::copy_nonoverlapping(name.as_ptr(), filename, name.len()) };
    // SAFETY: Both fixture-owned handles and the initialized buffer remain
    // live for the call, and io_status is a writable output structure.
    unsafe {
        NtSetInformationFile(
            HANDLE(source.as_raw_handle()),
            &raw mut io_status,
            info.cast(),
            u32::try_from(size).unwrap(),
            FileRenameInformation,
        )
    }
}

#[test]
#[ignore = "manual Windows filesystem capability probe; does not prove crash durability"]
fn relative_directory_rename_is_no_replace() {
    let base = fixture_base();
    fs::create_dir_all(&base).unwrap();
    let base = fs::canonicalize(base).unwrap();
    let dir = tempfile::Builder::new()
        .prefix("rename-")
        .tempdir_in(&base)
        .unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    assert!(root.starts_with(&base) && root != base);
    let first = root.join("stage-one");
    let second = root.join("stage-two");
    let destination = root.join("published");
    fs::create_dir(&first).unwrap();
    fs::create_dir(&second).unwrap();
    fs::write(first.join("first.txt"), b"first").unwrap();
    fs::write(second.join("second.txt"), b"second").unwrap();
    assert!(fs::canonicalize(&first).unwrap().starts_with(&root));
    assert!(fs::canonicalize(&second).unwrap().starts_with(&root));
    assert_eq!(destination.parent().unwrap(), root);
    let parent = open_directory(&root, false).unwrap();
    let first_handle = open_directory(&first, true).unwrap();
    rename_relative(&first_handle, &parent, "published")
        .expect("handle-relative rename to absent name");
    assert_eq!(fs::read(destination.join("first.txt")).unwrap(), b"first");
    let second_handle = open_directory(&second, true).unwrap();
    let _error = rename_relative(&second_handle, &parent, "published").unwrap_err();
    assert_eq!(fs::read(destination.join("first.txt")).unwrap(), b"first");
    assert_eq!(fs::read(second.join("second.txt")).unwrap(), b"second");
}

#[test]
#[ignore = "manual native Windows filesystem probe; does not prove crash durability"]
fn native_relative_directory_rename_is_no_replace() {
    let base = fixture_base();
    fs::create_dir_all(&base).unwrap();
    let base = fs::canonicalize(base).unwrap();
    let dir = tempfile::Builder::new()
        .prefix("native-rename-")
        .tempdir_in(&base)
        .unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    assert!(root.starts_with(&base) && root != base);
    let first = root.join("stage-one");
    let second = root.join("stage-two");
    let destination = root.join("published");
    fs::create_dir(&first).unwrap();
    fs::create_dir(&second).unwrap();
    fs::write(first.join("first.txt"), b"first").unwrap();
    fs::write(second.join("second.txt"), b"second").unwrap();
    assert!(fs::canonicalize(&first).unwrap().starts_with(&root));
    assert!(fs::canonicalize(&second).unwrap().starts_with(&root));
    assert_eq!(destination.parent().unwrap(), root);
    let parent = open_directory(&root, false).unwrap();
    let first_handle = open_directory(&first, true).unwrap();
    let stage_identity = directory_identity(&first_handle).unwrap();
    let parent_identity = directory_identity(&parent).unwrap();
    let status = nt_rename_relative(&first_handle, &parent, "published");
    assert_eq!(status.0, 0, "native relative rename failed: {status:?}");
    let published_handle = open_directory(&destination, false).unwrap();
    assert_eq!(
        directory_identity(&published_handle).unwrap(),
        stage_identity
    );
    assert_eq!(directory_identity(&first_handle).unwrap(), stage_identity);
    assert_eq!(directory_identity(&parent).unwrap(), parent_identity);
    assert_eq!(fs::read(destination.join("first.txt")).unwrap(), b"first");
    let second_handle = open_directory(&second, true).unwrap();
    let status = nt_rename_relative(&second_handle, &parent, "published");
    assert_eq!(status, STATUS_OBJECT_NAME_COLLISION);
    assert_eq!(
        directory_identity(&published_handle).unwrap(),
        stage_identity
    );
    assert_ne!(directory_identity(&second_handle).unwrap(), stage_identity);
    assert_eq!(fs::read(destination.join("first.txt")).unwrap(), b"first");
    assert_eq!(fs::read(second.join("second.txt")).unwrap(), b"second");
}

#[test]
#[ignore = "manual native Windows recovery probe; does not establish production isolation or crash durability"]
#[expect(
    clippy::too_many_lines,
    reason = "keep the complete synthetic commit and recovery sequence visible together"
)]
fn persisted_intent_matches_renamed_synthetic_stage_after_reopen() {
    let base = fixture_base();
    fs::create_dir_all(&base).unwrap();
    let base = fs::canonicalize(base).unwrap();
    let dir = tempfile::Builder::new()
        .prefix("intent-rename-")
        .tempdir_in(&base)
        .unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    assert!(root.starts_with(&base) && root != base);
    let stage_path = root.join("stage");
    let final_path = root.join("published");
    let journal_path = root.join("journal");
    fs::create_dir(&stage_path).unwrap();
    fs::write(stage_path.join("a.bin"), b"hello").unwrap();
    File::create(&journal_path).unwrap();
    let parent = open_directory(&root, false).unwrap();
    let stage = open_directory(&stage_path, true).unwrap();
    let parent_id = directory_identity(&parent).unwrap();
    let stage_id = directory_identity(&stage).unwrap();
    let journal_id = regular_file_identity(&File::open(&journal_path).unwrap()).unwrap();
    let file_id = regular_file_identity(&File::open(stage_path.join("a.bin")).unwrap()).unwrap();
    let object_id = |id: teamy_mover::transfer::windows_lock::FileIdentity| ObjectIdentity {
        volume_serial: id.volume_serial,
        file_index: id.file_index,
    };
    let transaction_id = "0123456789abcdef0123456789abcdef";
    let pin = "1111111111111111111111111111111111111111111111111111111111111111";
    let hash = format!("{:x}", Sha256::digest(b"hello"));
    let manifest = format!(
        r#"{{"aggregate_bytes":5,"expires_unix":100,"file_count":1,"files":[{{"id":"one","name":"a.bin","sha256":"{hash}","size":5}}],"transaction_id":"{transaction_id}","version":1}}"#
    );
    let digest = format!("{:x}", Sha256::digest(manifest.as_bytes()));
    let approval = JournalApproval {
        manifest_bytes: manifest.as_bytes(),
        manifest_sha256: &digest,
        transaction_id,
        client_pin: pin,
        server_pin: pin,
        destination_parent: object_id(parent_id),
        stage_directory: object_id(stage_id),
        journal_file: object_id(journal_id),
        final_name: "published",
        now_unix: 1,
    };
    let lock = || ExclusiveFile::acquire(&journal_path, journal_id).unwrap();
    let mut journal = TransactionJournal::initialize(lock(), &approval).unwrap();
    let mut body = OpenOptions::new()
        .read(true)
        .write(true)
        .open(stage_path.join("a.bin"))
        .unwrap();
    journal.verify_file("one", &mut body, 1).unwrap();
    journal.record_commit_intent(2).unwrap();
    drop(body);
    assert_eq!(nt_rename_relative(&stage, &parent, "published").0, 0);
    drop(journal);
    let mut recovered = TransactionJournal::reopen(lock(), &approval).unwrap();
    let mut published = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(&final_path)
        .unwrap();
    assert!(recovered.intent_matches_directory(&published).unwrap());
    assert!(!recovered.intent_matches_directory(&parent).unwrap());
    verify_entries(
        &mut published,
        stage_id,
        &[ExpectedEntry {
            name: "a.bin",
            identity: file_id,
            size: 5,
        }],
    )
    .unwrap();
    let mut body = OpenOptions::new()
        .read(true)
        .write(true)
        .open(final_path.join("a.bin"))
        .unwrap();
    recovered.reverify_intent_file("one", &mut body, 3).unwrap();
    drop(body);
    fs::write(final_path.join("extra.bin"), b"unexpected").unwrap();
    assert!(
        verify_entries(
            &mut published,
            stage_id,
            &[ExpectedEntry {
                name: "a.bin",
                identity: file_id,
                size: 5
            }],
        )
        .is_err()
    );
    fs::remove_file(final_path.join("extra.bin")).unwrap();
    fs::write(final_path.join("a.bin"), b"HELLO").unwrap();
    let mut changed = OpenOptions::new()
        .read(true)
        .write(true)
        .open(final_path.join("a.bin"))
        .unwrap();
    assert!(
        recovered
            .reverify_intent_file("one", &mut changed, 3)
            .is_err()
    );
    assert!(recovered.commit().is_err());
}

#[test]
#[ignore = "manual Windows race probe; does not prove crash durability"]
fn native_relative_no_replace_has_one_winner_under_collision() {
    let base = fixture_base();
    fs::create_dir_all(&base).unwrap();
    let base = fs::canonicalize(base).unwrap();
    for _ in 0..8 {
        let dir = tempfile::Builder::new()
            .prefix("rename-race-")
            .tempdir_in(&base)
            .unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        assert!(root.starts_with(&base) && root != base);
        let first = root.join("stage-one");
        let second = root.join("stage-two");
        let destination = root.join("published");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        fs::write(first.join("first.txt"), b"first").unwrap();
        fs::write(second.join("second.txt"), b"second").unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let workers: Vec<_> = [&first, &second]
            .into_iter()
            .map(|source| {
                let source = open_directory(source, true).unwrap();
                let parent = open_directory(&root, false).unwrap();
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    nt_rename_relative(&source, &parent, "published")
                })
            })
            .collect();
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|status| status.0 == 0).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|status| **status == STATUS_OBJECT_NAME_COLLISION)
                .count(),
            1
        );
        if first.exists() {
            assert_eq!(fs::read(first.join("first.txt")).unwrap(), b"first");
            assert_eq!(fs::read(destination.join("second.txt")).unwrap(), b"second");
        } else {
            assert_eq!(fs::read(second.join("second.txt")).unwrap(), b"second");
            assert_eq!(fs::read(destination.join("first.txt")).unwrap(), b"first");
        }
    }
}

#[test]
#[ignore = "manual Windows sharing probe; does not prove staging isolation"]
fn native_rename_with_exclusively_held_stage_and_file() {
    let base = fixture_base();
    fs::create_dir_all(&base).unwrap();
    let base = fs::canonicalize(base).unwrap();
    let dir = tempfile::Builder::new()
        .prefix("sharing-")
        .tempdir_in(&base)
        .unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    assert!(root.starts_with(&base) && root != base);
    let stage = root.join("stage");
    let destination = root.join("published");
    fs::create_dir(&stage).unwrap();
    let staged_file = stage.join("fixture.txt");
    fs::write(&staged_file, b"synthetic").unwrap();
    assert!(fs::canonicalize(&stage).unwrap().starts_with(&root));
    assert_eq!(destination.parent().unwrap(), root);

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(0)
        .open(&staged_file)
        .unwrap();
    let stage_handle = OpenOptions::new()
        .access_mode(DELETE.0 | FILE_READ_ATTRIBUTES.0)
        .share_mode(0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(&stage)
        .unwrap();
    let parent = open_directory(&root, false).unwrap();
    let mutation = OpenOptions::new().write(true).open(&staged_file);
    assert!(
        mutation.is_err(),
        "exclusive file allowed a competing writer"
    );
    let extra = stage.join("extra.txt");
    let extra_result = OpenOptions::new().write(true).create_new(true).open(&extra);
    eprintln!(
        "new child allowed while directory handle is exclusive: {}",
        extra_result.is_ok()
    );
    if let Ok(extra_file) = extra_result {
        drop(extra_file);
        fs::remove_file(&extra).unwrap();
    }
    let status = nt_rename_relative(&stage_handle, &parent, "published");
    eprintln!("rename with exclusive stage and file handles: {status:?}");
    drop(file);
    drop(stage_handle);
    if status.0 == 0 {
        assert_eq!(
            fs::read(destination.join("fixture.txt")).unwrap(),
            b"synthetic"
        );
    } else {
        assert_eq!(fs::read(staged_file).unwrap(), b"synthetic");
        assert!(!destination.exists());
    }
}

#[test]
#[ignore = "manual Windows sharing matrix; does not prove staging isolation"]
fn native_rename_with_delete_sharing_matrix() {
    let base = fixture_base();
    fs::create_dir_all(&base).unwrap();
    let base = fs::canonicalize(base).unwrap();
    let all_shares = FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0;
    for (stage_share, file_share) in [
        (0, FILE_SHARE_DELETE.0),
        (FILE_SHARE_DELETE.0, 0),
        (FILE_SHARE_DELETE.0, FILE_SHARE_DELETE.0),
        (all_shares, 0),
        (all_shares, FILE_SHARE_DELETE.0),
        (all_shares, all_shares),
    ] {
        let dir = tempfile::Builder::new()
            .prefix("matrix-")
            .tempdir_in(&base)
            .unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        assert!(root.starts_with(&base) && root != base);
        let stage = root.join("stage");
        let destination = root.join("published");
        fs::create_dir(&stage).unwrap();
        let staged_file = stage.join("fixture.txt");
        fs::write(&staged_file, b"synthetic").unwrap();
        assert!(fs::canonicalize(&stage).unwrap().starts_with(&root));
        assert_eq!(destination.parent().unwrap(), root);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(file_share)
            .open(&staged_file)
            .unwrap();
        let stage_handle = OpenOptions::new()
            .access_mode(DELETE.0 | FILE_READ_ATTRIBUTES.0)
            .share_mode(stage_share)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(&stage)
            .unwrap();
        let parent = open_directory(&root, false).unwrap();
        let delete_probe = OpenOptions::new()
            .access_mode(DELETE.0)
            .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0)
            .open(&staged_file);
        let competing_delete_open = delete_probe.is_ok();
        drop(delete_probe);
        let status = nt_rename_relative(&stage_handle, &parent, "published");
        eprintln!(
            "stage share={stage_share}, file share={file_share}, competing file DELETE open={competing_delete_open}, rename={status:?}"
        );
        drop(file);
        drop(stage_handle);
        if status.0 == 0 {
            assert_eq!(
                fs::read(destination.join("fixture.txt")).unwrap(),
                b"synthetic"
            );
        } else {
            assert_eq!(fs::read(staged_file).unwrap(), b"synthetic");
            assert!(!destination.exists());
        }
    }
}
