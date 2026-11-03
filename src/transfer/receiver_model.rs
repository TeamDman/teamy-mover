//! Test-only state machine using atomic, volatile simulated storage.
//! It cannot open files, listen, authenticate TLS peers, publish or delete.
//! A successful simulated commit is not evidence of filesystem durability.

use super::manifest::ApprovedManifest;
use super::manifest::parse_approved_manifest;
use super::verified_stream::FileVerifier;
use super::verified_stream::MAX_CHUNK_BYTES;
use eyre::Result;
use eyre::bail;
use eyre::ensure;
use facet::Facet;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Approved,
    Receiving,
    Verified,
    CommitIntent,
    Published,
    ReceiptRecorded,
    Aborted,
}

#[derive(Clone)]
struct FileRecord {
    identity: u64,
    body: Vec<u8>,
}

#[derive(Clone)]
struct Snapshot {
    transaction: String,
    manifest_digest: String,
    client_pin: String,
    sequence: u64,
    phase: Phase,
    files: BTreeMap<String, FileRecord>,
    receipt: Option<Vec<u8>>,
}

#[derive(Clone, Copy)]
enum Fault {
    Before(usize),
    After(usize),
}

#[derive(Default)]
struct FakeDisk {
    record: Option<Snapshot>,
    writes: usize,
    fault: Option<Fault>,
}

impl FakeDisk {
    fn save(&mut self, state: &Snapshot) -> Result<()> {
        self.writes += 1;
        if matches!(self.fault, Some(Fault::Before(n)) if n == self.writes) {
            bail!("simulated failure before write");
        }
        self.record = Some(state.clone());
        if matches!(self.fault, Some(Fault::After(n)) if n == self.writes) {
            bail!("simulated uncertain write");
        }
        Ok(())
    }
}

struct Model {
    manifest: ApprovedManifest,
    state: Snapshot,
    poisoned: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum Status {
    Receiving,
    Inspect,
    Aborted,
    Receipt(Vec<u8>),
}

#[derive(Facet)]
struct ReceiptFile<'a> {
    id: &'a str,
    sha256: &'a str,
    size: u64,
}

#[derive(Facet)]
struct Receipt<'a> {
    files: Vec<ReceiptFile<'a>>,
    manifest_sha256: &'a str,
    outcome: &'static str,
    transaction_id: &'a str,
    version: u32,
}

impl Model {
    fn start(
        disk: &mut FakeDisk,
        raw: &[u8],
        digest: &str,
        id: &str,
        pin: &str,
        now: u64,
    ) -> Result<Self> {
        ensure!(disk.record.is_none(), "transaction already exists");
        ensure!(
            pin.len() == 64
                && pin
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid pin"
        );
        let manifest = parse_approved_manifest(raw, digest, id, now)?;
        let state = Snapshot {
            transaction: id.into(),
            manifest_digest: digest.into(),
            client_pin: pin.into(),
            sequence: 1,
            phase: Phase::Approved,
            files: BTreeMap::new(),
            receipt: None,
        };
        disk.save(&state)?;
        Ok(Self {
            manifest,
            state,
            poisoned: false,
        })
    }

    fn restart(
        disk: &FakeDisk,
        raw: &[u8],
        digest: &str,
        id: &str,
        pin: &str,
        now: u64,
    ) -> Result<Self> {
        let manifest = parse_approved_manifest(raw, digest, id, now)?;
        let state = disk
            .record
            .clone()
            .ok_or_else(|| eyre::eyre!("missing record"))?;
        ensure!(
            state.transaction == id
                && state.manifest_digest == digest
                && state.client_pin == pin
                && state.sequence > 0,
            "record binding mismatch"
        );
        let model = Self {
            manifest,
            state,
            poisoned: false,
        };
        model.verify_stored()?;
        match model.state.phase {
            Phase::Approved => ensure!(model.state.files.is_empty(), "invalid approved state"),
            Phase::Receiving => ensure!(!model.state.files.is_empty(), "invalid receiving state"),
            Phase::Verified | Phase::CommitIntent | Phase::Published | Phase::ReceiptRecorded => {
                ensure!(model.all_present(), "incomplete commit state");
            }
            Phase::Aborted => {}
        }
        if model.state.phase == Phase::ReceiptRecorded {
            ensure!(
                model.all_present() && model.state.receipt.as_ref() == Some(&model.receipt()?),
                "invalid simulated receipt"
            );
        } else {
            ensure!(model.state.receipt.is_none(), "unexpected receipt");
        }
        Ok(model)
    }

    fn authorize(&self, id: &str, digest: &str, pin: &str, now: u64) -> Result<()> {
        ensure!(!self.poisoned, "recovery required");
        ensure!(now < self.manifest.expires_unix(), "expired");
        ensure!(
            id == self.state.transaction
                && digest == self.state.manifest_digest
                && pin == self.state.client_pin,
            "binding mismatch"
        );
        Ok(())
    }

    fn save(&mut self, disk: &mut FakeDisk, mut next: Snapshot) -> Result<()> {
        next.sequence = self
            .state
            .sequence
            .checked_add(1)
            .ok_or_else(|| eyre::eyre!("sequence overflow"))?;
        // A failed write can have happened: never continue on this process.
        self.poisoned = true;
        disk.save(&next)?;
        self.state = next;
        self.poisoned = false;
        Ok(())
    }

    fn verify_body(&self, id: &str, chunks: &[&[u8]]) -> Result<Vec<u8>> {
        let file = self
            .manifest
            .files()
            .find(|f| f.id() == id)
            .ok_or_else(|| eyre::eyre!("unknown file"))?;
        let mut verifier = FileVerifier::new(file, Vec::new());
        for chunk in chunks {
            verifier.push(chunk)?;
        }
        verifier.finish()
    }

    fn verify_stored(&self) -> Result<()> {
        let mut ids = BTreeSet::new();
        for (id, record) in &self.state.files {
            ensure!(
                record.identity != 0 && ids.insert(record.identity),
                "invalid synthetic file identity"
            );
            let chunks: Vec<_> = record.body.chunks(MAX_CHUNK_BYTES).collect();
            self.verify_body(id, &chunks)?;
        }
        Ok(())
    }

    fn all_present(&self) -> bool {
        self.state.files.len() == self.manifest.files().len()
    }

    fn upload(
        &mut self,
        disk: &mut FakeDisk,
        id: &str,
        digest: &str,
        pin: &str,
        file: (&str, &[&[u8]]),
        now: u64,
    ) -> Result<()> {
        self.authorize(id, digest, pin, now)?;
        ensure!(
            matches!(self.state.phase, Phase::Approved | Phase::Receiving),
            "not receiving"
        );
        let (file_id, chunks) = file;
        let body = self.verify_body(file_id, chunks)?;
        if let Some(old) = self.state.files.get(file_id) {
            ensure!(old.body == body, "conflicting duplicate");
            return Ok(());
        }
        let mut next = self.state.clone();
        let identity = next
            .files
            .values()
            .map(|record| record.identity)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| eyre::eyre!("identity overflow"))?;
        next.files
            .insert(file_id.to_owned(), FileRecord { identity, body });
        next.phase = Phase::Receiving;
        self.save(disk, next)
    }

    fn receipt(&self) -> Result<Vec<u8>> {
        let files = self
            .manifest
            .files()
            .map(|f| ReceiptFile {
                id: f.id(),
                sha256: f.sha256(),
                size: f.size(),
            })
            .collect();
        Ok(facet_json::to_string(&Receipt {
            files,
            manifest_sha256: &self.state.manifest_digest,
            outcome: "simulation-only",
            transaction_id: &self.state.transaction,
            version: 1,
        })?
        .into_bytes())
    }

    fn commit(
        &mut self,
        disk: &mut FakeDisk,
        id: &str,
        digest: &str,
        pin: &str,
        now: u64,
    ) -> Result<Vec<u8>> {
        self.authorize(id, digest, pin, now)?;
        if self.state.phase == Phase::ReceiptRecorded {
            return self.status(id, digest, pin, now).and_then(|s| match s {
                Status::Receipt(bytes) => Ok(bytes),
                _ => bail!("receipt unavailable"),
            });
        }
        ensure!(
            self.state.phase == Phase::Receiving && self.all_present(),
            "not ready"
        );
        self.verify_stored()?;
        for phase in [Phase::Verified, Phase::CommitIntent, Phase::Published] {
            let mut next = self.state.clone();
            next.phase = phase;
            self.save(disk, next)?;
        }
        let mut next = self.state.clone();
        next.phase = Phase::ReceiptRecorded;
        next.receipt = Some(self.receipt()?);
        self.save(disk, next)?;
        Ok(self.state.receipt.clone().expect("receipt just recorded"))
    }

    fn cancel(
        &mut self,
        disk: &mut FakeDisk,
        id: &str,
        digest: &str,
        pin: &str,
        now: u64,
    ) -> Result<()> {
        self.authorize(id, digest, pin, now)?;
        ensure!(
            matches!(
                self.state.phase,
                Phase::Approved | Phase::Receiving | Phase::Verified
            ),
            "publication may have happened"
        );
        let mut next = self.state.clone();
        next.phase = Phase::Aborted;
        self.save(disk, next)
    }

    fn status(&self, id: &str, digest: &str, pin: &str, now: u64) -> Result<Status> {
        self.authorize(id, digest, pin, now)?;
        Ok(match self.state.phase {
            Phase::Approved | Phase::Receiving => Status::Receiving,
            Phase::Verified | Phase::CommitIntent | Phase::Published => Status::Inspect,
            Phase::Aborted => Status::Aborted,
            Phase::ReceiptRecorded => {
                self.verify_stored()?;
                ensure!(
                    self.all_present() && self.state.receipt.as_ref() == Some(&self.receipt()?),
                    "invalid receipt"
                );
                Status::Receipt(self.state.receipt.clone().expect("receipt checked"))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;
    use sha2::Sha256;

    const ID: &str = "0123456789abcdef0123456789abcdef";
    const PIN: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const WRONG_PIN: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn approved() -> (String, String) {
        let first = format!("{:x}", Sha256::digest(b"hello"));
        let second = format!("{:x}", Sha256::digest(b"world"));
        let raw = format!(
            r#"{{"aggregate_bytes":10,"expires_unix":100,"file_count":2,"files":[{{"id":"one","name":"a.bin","sha256":"{first}","size":5}},{{"id":"two","name":"b.bin","sha256":"{second}","size":5}}],"transaction_id":"{ID}","version":1}}"#
        );
        let digest = format!("{:x}", Sha256::digest(raw.as_bytes()));
        (raw, digest)
    }

    fn prepared() -> (FakeDisk, Model, String, String) {
        let (raw, digest) = approved();
        let mut disk = FakeDisk::default();
        let mut model = Model::start(&mut disk, raw.as_bytes(), &digest, ID, PIN, 1).unwrap();
        model
            .upload(&mut disk, ID, &digest, PIN, ("one", &[b"he", b"llo"]), 1)
            .unwrap();
        model
            .upload(&mut disk, ID, &digest, PIN, ("two", &[b"world"]), 1)
            .unwrap();
        (disk, model, raw, digest)
    }

    #[test]
    fn retries_are_bound_and_identical_file_duplicates_are_idempotent() {
        let (mut disk, mut model, raw, digest) = prepared();
        let writes = disk.writes;
        model
            .upload(&mut disk, ID, &digest, PIN, ("one", &[b"hello"]), 2)
            .unwrap();
        assert_eq!(disk.writes, writes);
        assert!(
            model
                .upload(&mut disk, ID, &digest, PIN, ("one", &[b"other"]), 2)
                .is_err()
        );
        assert!(
            model
                .upload(&mut disk, ID, &digest, WRONG_PIN, ("one", &[b"hello"]), 2)
                .is_err()
        );
        let _error = model.status(ID, "wrong", PIN, 2).unwrap_err();
        let _error = model.status(ID, &digest, PIN, 100).unwrap_err();
        assert!(
            model
                .upload(&mut disk, ID, &digest, PIN, ("other", &[b"hello"]), 2)
                .is_err()
        );
        assert!(
            model
                .upload(
                    &mut disk,
                    ID,
                    &digest,
                    PIN,
                    ("one", &[&vec![0; MAX_CHUNK_BYTES + 1]]),
                    2
                )
                .is_err()
        );
        drop(model);
        let restarted = Model::restart(&disk, raw.as_bytes(), &digest, ID, PIN, 2).unwrap();
        assert_eq!(
            restarted.status(ID, &digest, PIN, 2).unwrap(),
            Status::Receiving
        );
        assert!(Model::restart(&disk, raw.as_bytes(), &digest, ID, WRONG_PIN, 2).is_err());
    }

    #[test]
    fn crash_at_each_simulated_commit_write_never_infers_a_receipt() {
        for fault_after in [false, true] {
            for boundary in 1..=4 {
                let (mut disk, mut model, raw, digest) = prepared();
                disk.fault = Some(if fault_after {
                    Fault::After(disk.writes + boundary)
                } else {
                    Fault::Before(disk.writes + boundary)
                });
                let _error = model.commit(&mut disk, ID, &digest, PIN, 2).unwrap_err();
                let _error = model.status(ID, &digest, PIN, 2).unwrap_err();
                let restarted = Model::restart(&disk, raw.as_bytes(), &digest, ID, PIN, 2).unwrap();
                let status = restarted.status(ID, &digest, PIN, 2).unwrap();
                if boundary == 1 && !fault_after {
                    assert_eq!(status, Status::Receiving);
                } else if boundary == 4 && fault_after {
                    assert!(matches!(status, Status::Receipt(_)));
                } else {
                    assert_eq!(status, Status::Inspect);
                }
            }
        }
    }

    #[test]
    fn lost_receipt_is_replayed_exactly_only_for_the_matching_binding_after_restart() {
        let (mut disk, mut model, raw, digest) = prepared();
        let receipt = model.commit(&mut disk, ID, &digest, PIN, 2).unwrap();
        assert_eq!(
            model.commit(&mut disk, ID, &digest, PIN, 2).unwrap(),
            receipt
        );
        assert!(model.cancel(&mut disk, ID, &digest, PIN, 2).is_err());
        drop(model);
        let restarted = Model::restart(&disk, raw.as_bytes(), &digest, ID, PIN, 3).unwrap();
        assert_eq!(
            restarted.status(ID, &digest, PIN, 3).unwrap(),
            Status::Receipt(receipt)
        );
        let _error = restarted.status(ID, &digest, WRONG_PIN, 3).unwrap_err();
        let state = disk.record.as_mut().unwrap();
        state.files.get_mut("one").unwrap().body[0] ^= 1;
        assert!(Model::restart(&disk, raw.as_bytes(), &digest, ID, PIN, 3).is_err());
    }

    #[test]
    fn cancellation_preserves_data_and_does_not_create_a_receipt() {
        let (mut disk, mut model, raw, digest) = prepared();
        model.cancel(&mut disk, ID, &digest, PIN, 2).unwrap();
        assert_eq!(model.state.files.len(), 2);
        let _error = model.commit(&mut disk, ID, &digest, PIN, 2).unwrap_err();
        let restarted = Model::restart(&disk, raw.as_bytes(), &digest, ID, PIN, 3).unwrap();
        assert_eq!(
            restarted.status(ID, &digest, PIN, 3).unwrap(),
            Status::Aborted
        );
        assert_eq!(restarted.state.files.len(), 2);
    }
}
