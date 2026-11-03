use sha2::Digest;
use sha2::Sha256;
use teamy_mover::transfer::manifest::ApprovedManifest;
use teamy_mover::transfer::manifest::parse_approved_manifest;
use teamy_mover::transfer::session::BodySetVerifier;

const ID: &str = "0123456789abcdef0123456789abcdef";

fn approved() -> ApprovedManifest {
    let first = format!("{:x}", Sha256::digest(b"hello"));
    let second = format!("{:x}", Sha256::digest(b"world"));
    let raw = format!(
        r#"{{"aggregate_bytes":10,"expires_unix":100,"file_count":2,"files":[{{"id":"one","name":"a.bin","sha256":"{first}","size":5}},{{"id":"two","name":"b.bin","sha256":"{second}","size":5}}],"transaction_id":"{ID}","version":1}}"#
    );
    let digest = format!("{:x}", Sha256::digest(raw.as_bytes()));
    parse_approved_manifest(raw.as_bytes(), &digest, ID, 1).unwrap()
}

#[test]
fn verifies_each_approved_body_once_in_either_order() {
    let mut session = BodySetVerifier::new(approved(), 1).unwrap();
    assert!(!session.all_bodies_checked(1));
    session.begin("two", Vec::new(), 2).unwrap();
    session.push(b"world", 3).unwrap();
    assert_eq!(session.finish(4).unwrap(), b"world");
    assert!(!session.all_bodies_checked(4));
    session.begin("one", Vec::new(), 5).unwrap();
    session.push(b"he", 6).unwrap();
    session.push(b"llo", 7).unwrap();
    assert_eq!(session.finish(8).unwrap(), b"hello");
    assert!(session.all_bodies_checked(9));
    assert!(!session.all_bodies_checked(100));
    assert!(!session.all_bodies_checked(99));
}

#[test]
fn unknown_duplicate_and_overlapping_bodies_poison_the_session() {
    let mut unknown = BodySetVerifier::new(approved(), 1).unwrap();
    let _error = unknown.begin("other", Vec::new(), 1).unwrap_err();
    let _error = unknown.begin("one", Vec::new(), 1).unwrap_err();

    let mut overlap = BodySetVerifier::new(approved(), 1).unwrap();
    overlap.begin("one", Vec::new(), 1).unwrap();
    let _error = overlap.begin("two", Vec::new(), 1).unwrap_err();
    let _error = overlap.push(b"hello", 1).unwrap_err();

    let mut duplicate = BodySetVerifier::new(approved(), 1).unwrap();
    duplicate.begin("one", Vec::new(), 1).unwrap();
    duplicate.push(b"hello", 1).unwrap();
    duplicate.finish(1).unwrap();
    let _error = duplicate.begin("one", Vec::new(), 1).unwrap_err();
    assert!(!duplicate.all_bodies_checked(1));
}

#[test]
fn expiry_missing_body_and_digest_failure_never_complete_a_session() {
    let _error = BodySetVerifier::<Vec<u8>>::new(approved(), 100).unwrap_err();
    let mut expired = BodySetVerifier::new(approved(), 1).unwrap();
    expired.begin("one", Vec::new(), 1).unwrap();
    let _error = expired.push(b"hello", 100).unwrap_err();
    let _error = expired.push(b"hello", 1).unwrap_err();

    let mut missing = BodySetVerifier::<Vec<u8>>::new(approved(), 1).unwrap();
    let _error = missing.push(b"hello", 1).unwrap_err();
    assert!(!missing.all_bodies_checked(1));

    let mut corrupt = BodySetVerifier::new(approved(), 1).unwrap();
    corrupt.begin("one", Vec::new(), 1).unwrap();
    corrupt.push(b"HELLO", 1).unwrap();
    let _error = corrupt.finish(1).unwrap_err();
    assert!(!corrupt.all_bodies_checked(1));
    let _error = corrupt.begin("two", Vec::new(), 1).unwrap_err();
}
