#![cfg(windows)]
//! Read-only diagnostic of one locally selected directory's ACL. This does
//! not qualify its ancestry, effective privileges, or publication safety.

use std::fs::OpenOptions;
use std::os::windows::fs::OpenOptionsExt;
use teamy_mover::transfer::windows_acl::{
    inspect_root_acl_candidate, process_user_sid, verify_directory_acl,
};
use teamy_mover::transfer::windows_lock::directory_identity;
use windows::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL,
};

#[test]
#[ignore = "read-only local ACL diagnostic; not an ancestry or publication qualification"]
fn selected_directory_acl_matches_local_expectation() {
    let path = std::env::var_os("TEAMY_TEST_ACL_TARGET").expect("select a local directory");
    let expectation = std::env::var("TEAMY_TEST_ACL_EXPECT").expect("select safe or unsafe");
    assert!(expectation == "safe" || expectation == "unsafe");
    let directory = OpenOptions::new()
        .access_mode((READ_CONTROL | FILE_READ_ATTRIBUTES).0)
        .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
        .expect("open selected directory without following its final reparse point");
    directory_identity(&directory).expect("selected handle is a non-reparse directory");
    let sid = process_user_sid().expect("inspect process user SID");
    let result = verify_directory_acl(&directory, &sid, false);
    assert_eq!(
        result.is_ok(),
        expectation == "safe",
        "ACL result: {result:?}"
    );
}

#[test]
#[ignore = "read-only root ACL candidate diagnostic; never authorizes publication"]
fn selected_root_acl_candidate_matches_local_expectation() {
    let path = std::env::var_os("TEAMY_TEST_ACL_TARGET").expect("select a local directory");
    let expectation = std::env::var("TEAMY_TEST_ACL_EXPECT").expect("select safe or unsafe");
    assert!(expectation == "safe" || expectation == "unsafe");
    let directory = OpenOptions::new()
        .access_mode((READ_CONTROL | FILE_READ_ATTRIBUTES).0)
        .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
        .expect("open selected directory without following its final reparse point");
    directory_identity(&directory).expect("selected handle is a non-reparse directory");
    let sid = process_user_sid().expect("inspect process user SID");
    let result = inspect_root_acl_candidate(&directory, &sid);
    assert_eq!(
        result.is_ok(),
        expectation == "safe",
        "ACL result: {result:?}"
    );
}
