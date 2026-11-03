use sha2::Digest;
use sha2::Sha256;
use std::fs::OpenOptions;
use std::io::Write;
use teamy_mover::transfer::journal::JournalApproval;
use teamy_mover::transfer::journal::JournalBinding;
use teamy_mover::transfer::journal::JournalPhase;
use teamy_mover::transfer::journal::ObjectIdentity;
use teamy_mover::transfer::journal_file::JournalFile;

const ID: &str = "0123456789abcdef0123456789abcdef";
const HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const PIN: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn binding() -> JournalBinding {
    let manifest = format!(
        r#"{{"aggregate_bytes":1,"expires_unix":100,"file_count":1,"files":[{{"id":"one","name":"a.bin","sha256":"{HASH}","size":1}}],"transaction_id":"{ID}","version":1}}"#
    );
    let digest = format!("{:x}", Sha256::digest(manifest.as_bytes()));
    JournalBinding::from_approval(&JournalApproval {
        manifest_bytes: manifest.as_bytes(),
        manifest_sha256: &digest,
        transaction_id: ID,
        client_pin: PIN,
        server_pin: PIN,
        destination_parent: ObjectIdentity {
            volume_serial: 1,
            file_index: 1,
        },
        stage_directory: ObjectIdentity {
            volume_serial: 1,
            file_index: 2,
        },
        journal_file: ObjectIdentity {
            volume_serial: 1,
            file_index: 3,
        },
        final_name: "recovered",
        now_unix: 1,
    })
    .unwrap()
}

#[test]
fn syncs_prepublication_transitions_and_reopens_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("journal");
    let file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let approved = binding();
    let mut journal = JournalFile::initialize(file, &approved, 1).unwrap();
    assert_eq!(journal.phase(), JournalPhase::Approved);
    journal.advance(JournalPhase::Receiving, 1).unwrap();
    drop(journal);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let mut restarted = JournalFile::reopen(file, &approved, 2).unwrap();
    assert_eq!(restarted.phase(), JournalPhase::Receiving);
    assert!(restarted.advance(JournalPhase::Verified, 2).is_err());
    restarted.advance(JournalPhase::Aborted, 2).unwrap();
    assert!(restarted.advance(JournalPhase::Aborted, 2).is_err());
    drop(restarted);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    assert_eq!(
        JournalFile::reopen(file, &approved, 2).unwrap().phase(),
        JournalPhase::Aborted
    );
}

#[test]
fn truncated_or_mutated_journal_is_preserved_and_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("journal");
    let file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let approved = binding();
    let mut journal = JournalFile::initialize(file, &approved, 1).unwrap();
    OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"TM")
        .unwrap();
    assert!(journal.advance(JournalPhase::Receiving, 1).is_err());
    assert!(journal.advance(JournalPhase::Receiving, 1).is_err());
    drop(journal);
    let before = std::fs::read(&path).unwrap();
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let _error = JournalFile::reopen(file, &approved, 1).unwrap_err();
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn expiry_blocks_advance_and_recovery_without_altering_the_record() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("journal");
    let file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let approved = binding();
    let mut journal = JournalFile::initialize(file, &approved, 1).unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(journal.advance(JournalPhase::Receiving, 100).is_err());
    assert!(journal.advance(JournalPhase::Receiving, 1).is_err());
    drop(journal);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let _error = JournalFile::reopen(file, &approved, 100).unwrap_err();
    assert_eq!(std::fs::read(&path).unwrap(), before);
}
