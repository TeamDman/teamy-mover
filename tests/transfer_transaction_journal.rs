#![cfg(windows)]

use sha2::Digest;
use sha2::Sha256;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::path::PathBuf;
use teamy_mover::transfer::journal::JournalApproval;
use teamy_mover::transfer::journal::ObjectIdentity;
use teamy_mover::transfer::transaction_journal::TransactionJournal;
use teamy_mover::transfer::windows_lock::ExclusiveFile;
use teamy_mover::transfer::windows_lock::FileIdentity;
use teamy_mover::transfer::windows_lock::regular_file_identity;

const ID: &str = "0123456789abcdef0123456789abcdef";
const PIN: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const WRONG_PIN: &str = "2222222222222222222222222222222222222222222222222222222222222222";

struct Fixture {
    dir: tempfile::TempDir,
    journal: PathBuf,
    body: PathBuf,
    journal_identity: FileIdentity,
    manifest: String,
    digest: String,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("journal");
        let body = dir.path().join("body");
        File::create(&journal).unwrap();
        std::fs::write(&body, b"hello").unwrap();
        let journal_identity = regular_file_identity(&File::open(&journal).unwrap()).unwrap();
        let hash = format!("{:x}", Sha256::digest(b"hello"));
        let manifest = format!(
            r#"{{"aggregate_bytes":5,"expires_unix":100,"file_count":1,"files":[{{"id":"one","name":"a.bin","sha256":"{hash}","size":5}}],"transaction_id":"{ID}","version":1}}"#
        );
        let digest = format!("{:x}", Sha256::digest(manifest.as_bytes()));
        Self {
            dir,
            journal,
            body,
            journal_identity,
            manifest,
            digest,
        }
    }

    fn approval(&self, pin: &'static str, now: u64) -> JournalApproval<'_> {
        let index = self.journal_identity.file_index;
        let volume = self.journal_identity.volume_serial;
        JournalApproval {
            manifest_bytes: self.manifest.as_bytes(),
            manifest_sha256: &self.digest,
            transaction_id: ID,
            client_pin: pin,
            server_pin: PIN,
            destination_parent: ObjectIdentity {
                volume_serial: volume,
                file_index: index ^ (1 << 63),
            },
            stage_directory: ObjectIdentity {
                volume_serial: volume,
                file_index: index ^ (1 << 62),
            },
            journal_file: ObjectIdentity {
                volume_serial: volume,
                file_index: index,
            },
            final_name: "recovered",
            now_unix: now,
        }
    }

    fn lock(&self) -> ExclusiveFile {
        ExclusiveFile::acquire(&self.journal, self.journal_identity).unwrap()
    }
    fn body(&self) -> File {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.body)
            .unwrap()
    }
}

#[test]
fn real_file_observation_survives_reopen_and_requires_reverification() {
    let fixture = Fixture::new();
    let mut journal =
        TransactionJournal::initialize(fixture.lock(), &fixture.approval(PIN, 1)).unwrap();
    let mut body = fixture.body();
    journal.verify_file("one", &mut body, 1).unwrap();
    journal.verify_file("one", &mut body, 1).unwrap();
    assert!(journal.has_observation("one"));
    assert!(journal.commit().is_err());
    drop(journal);
    let committed_length = std::fs::metadata(&fixture.journal).unwrap().len();
    let mut restarted =
        TransactionJournal::reopen(fixture.lock(), &fixture.approval(PIN, 2)).unwrap();
    assert!(restarted.has_observation("one"));
    body.seek(SeekFrom::Start(0)).unwrap();
    body.write_all(b"HELLO").unwrap();
    assert!(restarted.verify_file("one", &mut body, 2).is_err());
    body.seek(SeekFrom::Start(0)).unwrap();
    body.write_all(b"hello").unwrap();
    restarted.verify_file("one", &mut body, 2).unwrap();
    let other_path = fixture.dir.path().join("other");
    std::fs::write(&other_path, b"hello").unwrap();
    let mut other = OpenOptions::new()
        .read(true)
        .write(true)
        .open(other_path)
        .unwrap();
    assert!(restarted.verify_file("one", &mut other, 2).is_err());
    drop(restarted);
    assert_eq!(
        std::fs::metadata(&fixture.journal).unwrap().len(),
        committed_length
    );
    let mut restarted =
        TransactionJournal::reopen(fixture.lock(), &fixture.approval(PIN, 2)).unwrap();
    restarted.abort(2).unwrap();
    assert!(restarted.verify_file("one", &mut body, 2).is_err());
}

#[test]
fn torn_append_and_wrong_approval_fail_without_repairing_the_journal() {
    let fixture = Fixture::new();
    let mut journal =
        TransactionJournal::initialize(fixture.lock(), &fixture.approval(PIN, 1)).unwrap();
    journal.verify_file("one", &mut fixture.body(), 1).unwrap();
    drop(journal);
    let _error =
        TransactionJournal::reopen(fixture.lock(), &fixture.approval(WRONG_PIN, 2)).unwrap_err();
    let _error =
        TransactionJournal::reopen(fixture.lock(), &fixture.approval(PIN, 100)).unwrap_err();
    OpenOptions::new()
        .append(true)
        .open(&fixture.journal)
        .unwrap()
        .write_all(b"TMJ2\0")
        .unwrap();
    let damaged = std::fs::read(&fixture.journal).unwrap();
    let _error = TransactionJournal::reopen(fixture.lock(), &fixture.approval(PIN, 2)).unwrap_err();
    assert_eq!(std::fs::read(&fixture.journal).unwrap(), damaged);
}

#[test]
fn claim_survives_reopen_and_partial_file_is_preserved_for_inspection() {
    let fixture = Fixture::new();
    let path = fixture.dir.path().join("partial");
    File::create(&path).unwrap();
    let file_id = regular_file_identity(&File::open(&path).unwrap()).unwrap();
    let mut held = ExclusiveFile::acquire(&path, file_id).unwrap();
    let mut journal =
        TransactionJournal::initialize(fixture.lock(), &fixture.approval(PIN, 1)).unwrap();
    journal.claim_empty_file("one", &mut held, 1).unwrap();
    journal.claim_empty_file("one", &mut held, 1).unwrap();
    assert!(journal.has_pending_claim("one"));
    assert!(!journal.has_observation("one"));
    drop(held);
    drop(journal);

    std::fs::write(&path, b"he").unwrap();
    let mut restarted =
        TransactionJournal::reopen(fixture.lock(), &fixture.approval(PIN, 2)).unwrap();
    assert!(restarted.has_pending_claim("one"));
    let mut held = ExclusiveFile::acquire(&path, file_id).unwrap();
    assert!(restarted.claim_empty_file("one", &mut held, 2).is_err());
    drop(held);
    assert_eq!(std::fs::read(&path).unwrap(), b"he");
    drop(restarted);

    std::fs::write(&path, b"hello").unwrap();
    let mut restarted =
        TransactionJournal::reopen(fixture.lock(), &fixture.approval(PIN, 2)).unwrap();
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    restarted.verify_file("one", &mut file, 2).unwrap();
    assert!(restarted.has_observation("one"));
    assert!(!restarted.has_pending_claim("one"));
}
