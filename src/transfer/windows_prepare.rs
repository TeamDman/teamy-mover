//! Bounded creation of a private work directory and its approved empty files.
//!
//! This does not qualify ancestry or a destination, initialize a journal,
//! authorize a listener, publish data, or delete a source. A caller must retain
//! all relevant ancestor handles and pass a locally approved manifest.

use super::blocking_io::BlockingIoGate;
use super::manifest::ApprovedManifest;
use super::windows_acl::{CreatedDirectory, create_private_child, create_private_file};
use super::windows_lock::{ExclusiveFile, FileIdentity, directory_identity};
use eyre::{Result, ensure};
use std::collections::BTreeMap;
use std::fs::File;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Owned resources remain together until journal initialization or inspection.
#[derive(Debug)]
pub(crate) struct PreparedFiles {
    pub(crate) work_parent: File,
    pub(crate) work_root: CreatedDirectory,
    pub(crate) stage: CreatedDirectory,
    pub(crate) journal: ExclusiveFile,
    pub(crate) files: BTreeMap<String, ExclusiveFile>,
    pub(crate) retained: Vec<File>,
}

/// Create exclusively, never reusing or replacing an existing directory.
/// On any failure, created entries are retained for inspection. A timeout or
/// cancellation poisons the gate; the worker retains all handles while an I/O
/// operation remains outstanding. This is not a qualification capability.
pub(crate) async fn prepare_files(
    work_parent: File,
    expected_parent: FileIdentity,
    manifest: ApprovedManifest,
    gate: BlockingIoGate,
    budget: Duration,
    retained: Vec<File>,
) -> Result<PreparedFiles> {
    ensure!(
        !budget.is_zero() && budget <= Duration::from_secs(30),
        "invalid preparation budget"
    );
    let deadline = Instant::now()
        .checked_add(budget)
        .ok_or_else(|| eyre::eyre!("preparation deadline overflow"))?;
    let worker_gate = gate.clone();
    gate.run(budget, move || {
        let check = || -> Result<()> {
            worker_gate.ensure_active()?;
            ensure!(Instant::now() < deadline, "preparation timed out");
            ensure!(
                SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() < manifest.expires_unix(),
                "approval expired"
            );
            Ok(())
        };
        check()?;
        ensure!(
            directory_identity(&work_parent)? == expected_parent,
            "work parent identity changed"
        );
        let work_name = format!("storytelling-{}", manifest.transaction_id());
        let work_root = create_private_child(&work_parent, expected_parent, &work_name)?;
        check()?;
        let work_id = directory_identity(&work_root)?;
        let stage = create_private_child(&work_root, work_id, "payload")?;
        check()?;
        let stage_id = directory_identity(&stage)?;
        let journal = create_private_file(&work_root, work_id, "journal.bin")?;
        check()?;
        let mut files = BTreeMap::new();
        for approved in manifest.files() {
            check()?;
            let file = create_private_file(&stage, stage_id, approved.name())?;
            ensure!(
                files.insert(approved.id().to_owned(), file).is_none(),
                "duplicate file ID"
            );
        }
        check()?;
        Ok(PreparedFiles {
            work_parent,
            work_root,
            stage,
            journal,
            files,
            retained,
        })
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transfer::manifest::parse_approved_manifest;
    use crate::transfer::windows_acl::create_synthetic_private_directory;
    use sha2::{Digest, Sha256};

    #[tokio::test]
    async fn creates_only_approved_empty_files_and_refuses_reuse() {
        let temp = tempfile::tempdir().unwrap();
        let parent = create_synthetic_private_directory(&temp.path().join("private")).unwrap();
        let parent_id = directory_identity(&parent).unwrap();
        let expiry = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;
        let transaction = "0123456789abcdef0123456789abcdef";
        let hash = format!("{:x}", Sha256::digest(b"one"));
        let raw = format!(
            r#"{{"aggregate_bytes":3,"expires_unix":{expiry},"file_count":1,"files":[{{"id":"one","name":"one.bin","sha256":"{hash}","size":3}}],"transaction_id":"{transaction}","version":1}}"#
        );
        let digest = format!("{:x}", Sha256::digest(raw.as_bytes()));
        let manifest =
            parse_approved_manifest(raw.as_bytes(), &digest, transaction, expiry - 600).unwrap();
        let duplicate = parent.try_clone().unwrap();
        let mut resources = prepare_files(
            parent,
            parent_id,
            manifest.clone(),
            BlockingIoGate::default(),
            Duration::from_secs(3),
            Vec::new(),
        )
        .await
        .unwrap();
        assert_eq!(resources.files.len(), 1);
        assert_eq!(
            resources
                .files
                .get_mut("one")
                .unwrap()
                .file_mut()
                .metadata()
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            directory_identity(&resources.work_parent).unwrap(),
            parent_id
        );
        assert_eq!(
            directory_identity(&resources.stage).unwrap().volume_serial,
            parent_id.volume_serial
        );
        assert_eq!(
            directory_identity(&resources.work_root)
                .unwrap()
                .volume_serial,
            parent_id.volume_serial
        );
        resources.journal.verify().unwrap();
        let _collision = prepare_files(
            duplicate,
            parent_id,
            manifest,
            BlockingIoGate::default(),
            Duration::from_secs(3),
            Vec::new(),
        )
        .await
        .unwrap_err();
        assert!(
            temp.path()
                .join("private")
                .join(format!("storytelling-{transaction}"))
                .is_dir()
        );
    }
}
