#![cfg(windows)]

use std::fs;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::process::Command;
use teamy_mover::transfer::windows_lock::ExclusiveFile;
use teamy_mover::transfer::windows_lock::FileIdentity;
use teamy_mover::transfer::windows_lock::regular_file_identity;

fn fixture() -> (tempfile::TempDir, PathBuf, FileIdentity) {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("journal-test-fixtures");
    fs::create_dir_all(&base).unwrap();
    let base = fs::canonicalize(base).unwrap();
    let dir = tempfile::Builder::new()
        .prefix("journal-")
        .tempdir_in(&base)
        .unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    assert!(root.starts_with(&base) && root != base);
    let path = root.join("journal.bin");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    let identity = regular_file_identity(&file).unwrap();
    (dir, path, identity)
}

fn child(path: &std::path::Path, identity: FileIdentity, should_succeed: bool) {
    let output = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("child_lock_probe")
        .env("TEAMY_TEST_JOURNAL_PATH", path)
        .env(
            "TEAMY_TEST_JOURNAL_VOLUME",
            identity.volume_serial.to_string(),
        )
        .env("TEAMY_TEST_JOURNAL_INDEX", identity.file_index.to_string())
        .env(
            "TEAMY_TEST_EXPECT_SUCCESS",
            if should_succeed { "yes" } else { "no" },
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn child_lock_probe() {
    let Some(path) = std::env::var_os("TEAMY_TEST_JOURNAL_PATH") else {
        return;
    };
    let volume_serial = std::env::var("TEAMY_TEST_JOURNAL_VOLUME")
        .unwrap()
        .parse()
        .unwrap();
    let file_index = std::env::var("TEAMY_TEST_JOURNAL_INDEX")
        .unwrap()
        .parse()
        .unwrap();
    let expected = std::env::var("TEAMY_TEST_EXPECT_SUCCESS").unwrap();
    let result = ExclusiveFile::acquire(
        &PathBuf::from(path),
        FileIdentity {
            volume_serial,
            file_index,
        },
    );
    assert_eq!(result.is_ok(), expected == "yes");
}

#[test]
fn lock_excludes_other_process_and_releases_without_deleting_file() {
    let (_dir, path, identity) = fixture();
    let held = ExclusiveFile::acquire(&path, identity).unwrap();
    held.verify().unwrap();
    child(&path, identity, false);
    drop(held);
    child(&path, identity, true);
    assert!(path.is_file());
}

#[test]
fn wrong_file_identity_is_rejected() {
    let (_dir, path, identity) = fixture();
    let wrong = FileIdentity {
        file_index: identity.file_index ^ 1,
        ..identity
    };
    let _error = ExclusiveFile::acquire(&path, wrong).unwrap_err();
    assert!(path.is_file());
}

#[test]
#[ignore = "requires permission to create a synthetic hard link"]
fn hard_linked_file_is_rejected() {
    let (dir, path, identity) = fixture();
    let link = dir.path().join("alias.bin");
    fs::hard_link(&path, &link).expect("create synthetic hard link");
    let _error = ExclusiveFile::acquire(&path, identity).unwrap_err();
    assert!(path.is_file() && link.is_file());
}

#[test]
#[ignore = "requires permission to create a synthetic symbolic link"]
fn final_component_reparse_point_is_rejected() {
    let (dir, path, identity) = fixture();
    let link = dir.path().join("alias.bin");
    assert_eq!(link.parent().unwrap(), dir.path());
    std::os::windows::fs::symlink_file(&path, &link).expect("create synthetic symbolic link");
    let _error = ExclusiveFile::acquire(&link, identity).unwrap_err();
    fs::remove_file(&link).expect("remove only the synthetic link");
    assert!(path.is_file());
}
