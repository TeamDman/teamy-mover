use sha2::Digest;
use sha2::Sha256;
use std::io;
use std::io::Write;
use teamy_mover::transfer::manifest::ApprovedManifest;
use teamy_mover::transfer::manifest::parse_approved_manifest;
use teamy_mover::transfer::verified_stream::FileVerifier;
use teamy_mover::transfer::verified_stream::MAX_CHUNK_BYTES;

const ID: &str = "0123456789abcdef0123456789abcdef";

fn approved(content: &[u8]) -> ApprovedManifest {
    let file_hash = format!("{:x}", Sha256::digest(content));
    let size = content.len();
    let raw = format!(
        r#"{{"aggregate_bytes":{size},"expires_unix":100,"file_count":1,"files":[{{"id":"one","name":"a.bin","sha256":"{file_hash}","size":{size}}}],"transaction_id":"{ID}","version":1}}"#
    );
    let digest = format!("{:x}", Sha256::digest(raw.as_bytes()));
    parse_approved_manifest(raw.as_bytes(), &digest, ID, 1).unwrap()
}

#[test]
fn verifies_multiple_chunks_and_empty_file() {
    let manifest = approved(b"hello world");
    let mut stream = FileVerifier::new(manifest.files().next().unwrap(), Vec::new());
    stream.push(b"hello ").unwrap();
    stream.push(b"world").unwrap();
    assert_eq!(stream.finish().unwrap(), b"hello world");

    let manifest = approved(b"");
    assert!(
        FileVerifier::new(manifest.files().next().unwrap(), Vec::new())
            .finish()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn rejects_short_corrupt_oversized_and_excess_bodies() {
    let manifest = approved(b"hello");
    let mut short = FileVerifier::new(manifest.files().next().unwrap(), Vec::new());
    short.push(b"hell").unwrap();
    let _error = short.finish().unwrap_err();

    let mut corrupt = FileVerifier::new(manifest.files().next().unwrap(), Vec::new());
    corrupt.push(b"HELLO").unwrap();
    let _error = corrupt.finish().unwrap_err();

    let mut excess = FileVerifier::new(manifest.files().next().unwrap(), Vec::new());
    let _error = excess.push(b"hello!").unwrap_err();
    let _error = excess.push(b"hello").unwrap_err();
    let _error = excess.finish().unwrap_err();

    let large = vec![0_u8; MAX_CHUNK_BYTES + 1];
    let manifest = approved(&large);
    let mut stream = FileVerifier::new(manifest.files().next().unwrap(), Vec::new());
    let _error = stream.push(&large).unwrap_err();
    let _error = stream.finish().unwrap_err();
}

#[derive(Debug)]
struct PartialFailure(bool);

impl Write for PartialFailure {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.0 {
            Err(io::Error::other("synthetic write failure"))
        } else {
            self.0 = true;
            Ok(buf.len().min(2))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn partial_io_failure_permanently_poisons_verifier() {
    let manifest = approved(b"hello");
    let mut stream = FileVerifier::new(manifest.files().next().unwrap(), PartialFailure(false));
    let _error = stream.push(b"hello").unwrap_err();
    let _error = stream.push(b"hello").unwrap_err();
    let _error = stream.finish().unwrap_err();
}

#[derive(Debug)]
struct FlushFailure;

impl Write for FlushFailure {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("synthetic flush failure"))
    }
}

#[test]
fn verification_requires_a_successful_flush() {
    let manifest = approved(b"hello");
    let mut stream = FileVerifier::new(manifest.files().next().unwrap(), FlushFailure);
    stream.push(b"hello").unwrap();
    let _error = stream.finish().unwrap_err();
}
