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
    assert!(Source::open("id".into(), &file).is_ok());
    let final_link = dir.path().join("file-link");
    symlink(&file, &final_link).unwrap();
    assert!(Source::open("id".into(), &final_link).is_err());
    let parent_link = dir.path().join("directory-link");
    symlink(&real, &parent_link).unwrap();
    assert!(Source::open("id".into(), &parent_link.join("file")).is_err());
    assert!(Source::open("id".into(), &real.join("..").join("real").join("file")).is_err());
    assert!(Source::open("id".into(), std::path::Path::new("relative")).is_err());
    let hard_link = dir.path().join("hard-link");
    std::fs::hard_link(&file, hard_link).unwrap();
    assert!(Source::open("id".into(), &file).is_err());
}
