use sha2::Digest;
use sha2::Sha256;
use teamy_mover::transfer::manifest::parse_approved_manifest;
use teamy_mover::transfer::manifest::valid_component;

const ID: &str = "0123456789abcdef0123456789abcdef";
const HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn file(id: &str, name: &str, size: u64) -> String {
    format!(r#"{{"id":"{id}","name":"{name}","sha256":"{HASH}","size":{size}}}"#)
}

fn manifest(files: &[String], total: u64, expires: u64) -> String {
    format!(
        r#"{{"aggregate_bytes":{total},"expires_unix":{expires},"file_count":{},"files":[{}],"transaction_id":"{ID}","version":1}}"#,
        files.len(),
        files.join(",")
    )
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn rejected(raw: &str) {
    assert!(
        parse_approved_manifest(raw.as_bytes(), &digest(raw.as_bytes()), ID, 1).is_err(),
        "invalid manifest was accepted"
    );
}

#[test]
fn accepts_a_canonical_manifest_bound_to_local_approval() {
    let raw = manifest(
        &[file("orbit", "orbit.mkv", 5), file("extra", "extra.bin", 0)],
        5,
        100,
    );
    let parsed = parse_approved_manifest(raw.as_bytes(), &digest(raw.as_bytes()), ID, 1).unwrap();
    assert_eq!(parsed.transaction_id(), ID);
    assert_eq!(parsed.expires_unix(), 100);
    assert_eq!(parsed.aggregate_bytes(), 5);
    let entries: Vec<_> = parsed.files().collect();
    assert_eq!(entries.len(), 2);
    assert_eq!(
        (entries[0].id(), entries[0].name(), entries[0].size()),
        ("orbit", "orbit.mkv", 5)
    );
    assert_eq!(entries[0].sha256(), HASH);
}

#[test]
fn rejects_wrong_approval_expiry_and_invalid_approved_inputs() {
    let raw = manifest(&[file("one", "a.bin", 1)], 1, 100);
    let _error = parse_approved_manifest(raw.as_bytes(), HASH, ID, 1).unwrap_err();
    let _error = parse_approved_manifest(
        raw.as_bytes(),
        &digest(raw.as_bytes()),
        "fedcba9876543210fedcba9876543210",
        1,
    )
    .unwrap_err();
    let _error =
        parse_approved_manifest(raw.as_bytes(), &digest(raw.as_bytes()), ID, 100).unwrap_err();
    let _error = parse_approved_manifest(raw.as_bytes(), "not-a-digest", ID, 1).unwrap_err();
    let _error =
        parse_approved_manifest(raw.as_bytes(), &digest(raw.as_bytes()), "bad-id", 1).unwrap_err();
}

#[test]
fn rejects_noncanonical_and_ambiguous_json() {
    let raw = manifest(&[file("one", "a.bin", 1)], 1, 100);
    rejected(&format!("{raw}\n"));
    rejected(&raw.replacen(
        "{\"aggregate_bytes\":1",
        "{\"version\":1,\"aggregate_bytes\":1",
        1,
    ));
    rejected(&raw.replacen(
        "{\"aggregate_bytes\":1",
        "{\"unknown\":0,\"aggregate_bytes\":1",
        1,
    ));
    rejected(&raw.replacen("\"one\"", "\"\\u006fne\"", 1));
    rejected(&raw.replacen("\"aggregate_bytes\":1", "\"aggregate_bytes\":1.0", 1));
    rejected(&raw.replacen("\"version\":1", "\"version\":2", 1));
}

#[test]
fn rejects_invalid_components_and_case_aliases() {
    for name in [
        "", ".", "..", "CON", "con.txt", "LPT9.a", "COM1", "bad.", "a/b", "a\\b", "a:b", "a b",
        "é.txt",
    ] {
        assert!(!valid_component(name), "unsafe filename accepted: {name:?}");
    }
    for name in ["ok.bin", "COM0.txt", "a-b_c.1", "NULx"] {
        assert!(valid_component(name), "valid filename rejected: {name:?}");
    }
    rejected(&manifest(
        &[file("one", "same.txt", 1), file("two", "SAME.TXT", 1)],
        2,
        100,
    ));
    rejected(&manifest(
        &[file("same", "a.txt", 1), file("same", "b.txt", 1)],
        2,
        100,
    ));
    rejected(&manifest(&[file("bad/identifier", "a.txt", 1)], 1, 100));
}

#[test]
fn rejects_wrong_counts_sizes_expiry_and_digest_syntax() {
    rejected(&manifest(&[], 0, 100));
    rejected(&manifest(&[file("one", "a.bin", 1)], 2, 100));
    rejected(&manifest(
        &[file("one", "a.bin", 64 * 1024 * 1024 + 1)],
        64 * 1024 * 1024 + 1,
        100,
    ));
    rejected(&manifest(&[file("one", "a.bin", 1)], 1, 1_u64 << 53));
    let raw = manifest(&[file("one", "a.bin", 1)], 1, 100);
    rejected(&raw.replace(HASH, &"A".repeat(64)));
    rejected(&raw.replace("\"file_count\":1", "\"file_count\":2"));
    let files: Vec<_> = (0..17)
        .map(|i| file(&format!("id{i}"), &format!("file{i}"), 1))
        .collect();
    rejected(&manifest(&files, 17, 100));
}

#[test]
fn rejects_overlong_input_before_parsing() {
    let bytes = vec![b' '; 64 * 1024 + 1];
    let _error = parse_approved_manifest(&bytes, &digest(&bytes), ID, 1).unwrap_err();
}
