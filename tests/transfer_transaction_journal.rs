#![cfg(windows)]

use sha2::Digest;
use sha2::Sha256;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::os::windows::fs::OpenOptionsExt;
use std::path::PathBuf;
use teamy_mover::transfer::journal::JournalApproval;
use teamy_mover::transfer::journal::ObjectIdentity;
use teamy_mover::transfer::recovery::RecoveryDisposition;
use teamy_mover::transfer::transaction_journal::LocalInspection;
use teamy_mover::transfer::transaction_journal::TransactionJournal;
use teamy_mover::transfer::windows_lock::ExclusiveFile;
use teamy_mover::transfer::windows_lock::FileIdentity;
use teamy_mover::transfer::windows_lock::directory_identity;
use teamy_mover::transfer::windows_lock::regular_file_identity;
use windows::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;
use windows::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

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

fn named_stream(path: &std::path::Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(":unexpected");
    PathBuf::from(name)
}

#[test]
fn unexpected_stream_prevents_file_observation() {
    let fixture = Fixture::new();
    std::fs::write(named_stream(&fixture.body), b"hidden").unwrap();
    let mut journal =
        TransactionJournal::initialize(fixture.lock(), &fixture.approval(PIN, 1)).unwrap();
    let _rejected = journal.verify_file("one", &mut fixture.body(), 1).unwrap_err();
    assert!(!journal.has_observation("one"));
    assert_eq!(std::fs::read(&fixture.body).unwrap(), b"hello");
}

#[test]
fn local_recovery_rejects_stream_added_after_commit_intent() {
    let fixture = Fixture::new();
    let mut journal =
        TransactionJournal::initialize(fixture.lock(), &fixture.approval(PIN, 1)).unwrap();
    journal.verify_file("one", &mut fixture.body(), 1).unwrap();
    journal.record_commit_intent(2).unwrap();
    drop(journal);
    std::fs::write(named_stream(&fixture.body), b"hidden").unwrap();
    let body_id = regular_file_identity(&File::open(&fixture.body).unwrap()).unwrap();
    let mut held = ExclusiveFile::acquire(&fixture.body, body_id).unwrap();
    let mut inspection = LocalInspection::open(fixture.lock(), &fixture.approval(PIN, 101)).unwrap();
    assert_eq!(
        inspection.disposition(),
        RecoveryDisposition::InspectAmbiguousPublication
    );
    let _rejected = inspection.verify_recorded_file("one", &mut held).unwrap_err();
    drop(held);
    assert_eq!(std::fs::read(&fixture.body).unwrap(), b"hello");
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

#[test]
fn commit_intent_persists_bound_stage_identity_without_claiming_publication() {
    let fixture = Fixture::new();
    let approval = fixture.approval(PIN, 1);
    let expected_stage = approval.stage_directory;
    let mut journal = TransactionJournal::initialize(fixture.lock(), &approval).unwrap();
    assert!(journal.record_commit_intent(1).is_err());
    assert_eq!(journal.commit_intent_stage(), None);
    journal.verify_file("one", &mut fixture.body(), 1).unwrap();
    assert!(journal.record_commit_intent(100).is_err());
    journal.record_commit_intent(2).unwrap();
    assert_eq!(journal.commit_intent_stage(), Some(expected_stage));
    assert!(journal.record_commit_intent(2).is_err());
    assert!(journal.abort(2).is_err());
    assert!(journal.verify_file("one", &mut fixture.body(), 2).is_err());
    assert!(journal.commit().is_err());
    drop(journal);

    let recorded = std::fs::read(&fixture.journal).unwrap();
    let mut reopened =
        TransactionJournal::reopen(fixture.lock(), &fixture.approval(PIN, 3)).unwrap();
    assert_eq!(reopened.commit_intent_stage(), Some(expected_stage));
    assert!(reopened.commit().is_err());
    reopened
        .reverify_intent_file("one", &mut fixture.body(), 3)
        .unwrap();
    let other_path = fixture.dir.path().join("different-identity");
    std::fs::write(&other_path, b"hello").unwrap();
    let mut other = OpenOptions::new()
        .read(true)
        .write(true)
        .open(other_path)
        .unwrap();
    assert!(reopened.reverify_intent_file("one", &mut other, 3).is_err());
    std::fs::write(&fixture.body, b"HELLO").unwrap();
    assert!(
        reopened
            .reverify_intent_file("one", &mut fixture.body(), 3)
            .is_err()
    );
    std::fs::write(&fixture.body, b"hello").unwrap();
    reopened
        .reverify_intent_file("one", &mut fixture.body(), 3)
        .unwrap();
    drop(reopened);
    assert_eq!(std::fs::read(&fixture.journal).unwrap(), recorded);
    assert_eq!(std::fs::read(&fixture.body).unwrap(), b"hello");

    let mut mismatched = fixture.approval(PIN, 3);
    mismatched.stage_directory.file_index ^= 1;
    let _error = TransactionJournal::reopen(fixture.lock(), &mismatched).unwrap_err();
    assert_eq!(std::fs::read(&fixture.journal).unwrap(), recorded);
}

#[test]
fn intent_matches_only_the_recorded_non_reparse_directory_handle() {
    let fixture = Fixture::new();
    let stage_path = fixture.dir.path().join("stage");
    let other_path = fixture.dir.path().join("other-stage");
    std::fs::create_dir(&stage_path).unwrap();
    std::fs::create_dir(&other_path).unwrap();
    let open_dir = |path: &std::path::Path| {
        OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(path)
            .unwrap()
    };
    let stage = open_dir(&stage_path);
    let other = open_dir(&other_path);
    let id = directory_identity(&stage).unwrap();
    let mut approval = fixture.approval(PIN, 1);
    approval.stage_directory = ObjectIdentity {
        volume_serial: id.volume_serial,
        file_index: id.file_index,
    };
    let mut journal = TransactionJournal::initialize(fixture.lock(), &approval).unwrap();
    let _missing_intent = journal.intent_matches_directory(&stage).unwrap_err();
    journal.verify_file("one", &mut fixture.body(), 1).unwrap();
    journal.record_commit_intent(2).unwrap();
    assert!(journal.intent_matches_directory(&stage).unwrap());
    assert!(!journal.intent_matches_directory(&other).unwrap());
    let _not_a_directory = journal
        .intent_matches_directory(&fixture.body())
        .unwrap_err();
    assert!(journal.commit().is_err());
}

#[test]
fn expired_approval_allows_read_only_local_inspection_but_not_live_reopen() {
    let mut fixture = Fixture::new();
    let stage_path = fixture.dir.path().join("stage");
    std::fs::create_dir(&stage_path).unwrap();
    let staged_body = stage_path.join("a.bin");
    std::fs::rename(&fixture.body, &staged_body).unwrap();
    fixture.body = staged_body;
    let stage = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(&stage_path)
        .unwrap();
    let stage_id = directory_identity(&stage).unwrap();
    let mut approval = fixture.approval(PIN, 1);
    approval.stage_directory = ObjectIdentity {
        volume_serial: stage_id.volume_serial,
        file_index: stage_id.file_index,
    };
    let mut journal = TransactionJournal::initialize(fixture.lock(), &approval).unwrap();
    journal.verify_file("one", &mut fixture.body(), 1).unwrap();
    journal.record_commit_intent(2).unwrap();
    drop(journal);
    let original_journal = std::fs::read(&fixture.journal).unwrap();
    let mut expired = fixture.approval(PIN, 100);
    expired.stage_directory = approval.stage_directory;
    let _live_reopen = TransactionJournal::reopen(fixture.lock(), &expired).unwrap_err();
    let mut wrong = fixture.approval(WRONG_PIN, 100);
    wrong.stage_directory = approval.stage_directory;
    let _wrong_pin = LocalInspection::open(fixture.lock(), &wrong).unwrap_err();
    let mut inspection = LocalInspection::open(fixture.lock(), &expired).unwrap();
    assert_eq!(
        inspection.disposition(),
        RecoveryDisposition::InspectAmbiguousPublication
    );
    assert!(inspection.intent_matches_directory(&stage).unwrap());
    let body_id = regular_file_identity(&File::open(&fixture.body).unwrap()).unwrap();
    let mut body = ExclusiveFile::acquire(&fixture.body, body_id).unwrap();
    inspection.verify_recorded_file("one", &mut body).unwrap();
    drop(body);
    let other = fixture.dir.path().join("same-bytes-other-file");
    std::fs::write(&other, b"hello").unwrap();
    let other_id = regular_file_identity(&File::open(&other).unwrap()).unwrap();
    let mut other_file = ExclusiveFile::acquire(&other, other_id).unwrap();
    let _identity = inspection
        .verify_recorded_file("one", &mut other_file)
        .unwrap_err();
    drop(other_file);
    std::fs::write(&fixture.body, b"HELLO").unwrap();
    let mut changed = ExclusiveFile::acquire(&fixture.body, body_id).unwrap();
    let _hash = inspection
        .verify_recorded_file("one", &mut changed)
        .unwrap_err();
    drop(changed);
    drop(inspection);
    assert_eq!(std::fs::read(&fixture.journal).unwrap(), original_journal);
    assert_eq!(std::fs::read(&fixture.body).unwrap(), b"HELLO");
    OpenOptions::new()
        .append(true)
        .open(&fixture.journal)
        .unwrap()
        .write_all(b"TMJ2\0")
        .unwrap();
    let torn = std::fs::read(&fixture.journal).unwrap();
    let _torn = LocalInspection::open(fixture.lock(), &expired).unwrap_err();
    assert_eq!(std::fs::read(&fixture.journal).unwrap(), torn);
}
