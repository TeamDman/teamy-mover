#![cfg(target_os = "linux")]

use std::os::unix::fs::symlink;
use teamy_mover::transfer::sender::Source;

#[test]
fn refuses_symlinks_hardlinks_relative_paths_and_parent_components() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let file = real.join("file");
    std::fs::write(&file, b"synthetic").unwrap();
    let _source = Source::open("id".into(), &file).unwrap();
    let final_link = dir.path().join("file-link");
    symlink(&file, &final_link).unwrap();
    let _error = Source::open("id".into(), &final_link).unwrap_err();
    let parent_link = dir.path().join("directory-link");
    symlink(&real, &parent_link).unwrap();
    let _error = Source::open("id".into(), &parent_link.join("file")).unwrap_err();
    let _error = Source::open("id".into(), &real.join("..").join("real").join("file")).unwrap_err();
    let _error = Source::open("id".into(), std::path::Path::new("relative")).unwrap_err();
    let hard_link = dir.path().join("hard-link");
    std::fs::hard_link(&file, hard_link).unwrap();
    let _error = Source::open("id".into(), &file).unwrap_err();
}
