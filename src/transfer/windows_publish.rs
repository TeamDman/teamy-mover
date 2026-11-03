//! Fail-closed Windows no-replace rename prototype.
//!
//! No operational `PublicationPermit` constructor exists. An independently
//! reviewed gate must establish ancestry, exact contents, token and handle
//! boundaries, filesystem semantics and recovery before any live use.

use super::blocking_io::BlockingIoGate;
use super::journal::{JournalBinding, ObjectIdentity};
use super::manifest::valid_component;
use super::transaction_journal::TransactionJournal;
use super::windows_acl::{CreatedDirectory, open_checked_child};
use super::windows_lock::{ExclusiveFile, directory_identity};
use eyre::{Result, ensure};
use std::collections::BTreeMap;
use std::fs::File;
use std::os::windows::io::AsRawHandle;
use std::time::Duration;
use windows::Wdk::Storage::FileSystem::{
    FILE_RENAME_INFORMATION, FILE_RENAME_INFORMATION_0, FileRenameInformation, NtSetInformationFile,
};
use windows::Win32::Foundation::{HANDLE, STATUS_PENDING};
use windows::Win32::System::IO::IO_STATUS_BLOCK;

/// Reserved for a future independently reviewed, single-use gate.
/// No operational constructor is provided.
#[derive(Debug)]
pub struct PublicationPermit(BlockingIoGate);

/// Resources that a future independently reviewed qualification gate must
/// construct as one bound unit. No operational constructor exists.
#[derive(Debug)]
pub struct QualifiedCommit {
    permit: PublicationPermit,
    journal: TransactionJournal,
    files: BTreeMap<String, ExclusiveFile>,
    stage: CreatedDirectory,
    destination_parent: File,
    ancestry: Vec<File>,
    final_name: String,
}

/// Retained resources from a future reviewed qualification decision. No
/// operational constructor exists; DACL diagnostics alone cannot create it.
pub(crate) struct PublicationQualification {
    permit: PublicationPermit,
    stage: CreatedDirectory,
    destination_parent: File,
    ancestry: Vec<File>,
    final_name: String,
}

impl PublicationQualification {
    /// Use the same single-flight gate for staging and publication. This does
    /// not create or qualify the permit.
    pub(crate) fn gate(&self) -> BlockingIoGate {
        self.permit.0.clone()
    }

    /// Check the bound journal identities before exposing a prepared receiver.
    /// A successful check does not prove ancestry or authorize publication.
    pub(crate) fn check_binding(&self, journal: &mut TransactionJournal) -> Result<()> {
        ensure!(
            !self.ancestry.is_empty() && self.ancestry.len() <= 64,
            "invalid retained ancestry"
        );
        journal.check_pre_intent_target(&self.destination_parent, &self.stage, &self.final_name)
    }

    pub(crate) fn bind(
        self,
        journal: TransactionJournal,
        files: BTreeMap<String, ExclusiveFile>,
    ) -> QualifiedCommit {
        QualifiedCommit {
            permit: self.permit,
            journal,
            files,
            stage: self.stage,
            destination_parent: self.destination_parent,
            ancestry: self.ancestry,
            final_name: self.final_name,
        }
    }
}

/// An observed rename outcome, never a power-loss durability guarantee.
#[derive(Debug, PartialEq, Eq)]
pub enum RenameOutcome {
    /// Windows reported success and an unconfirmed-durability receipt was persisted.
    RenamedDurabilityUnconfirmed,
    /// The rename succeeded, but observation or journal persistence failed.
    RenamedRecordUnconfirmed,
    /// Preserve the objects and reconcile locally; do not retry or issue a receipt.
    Unconfirmed { status: u32 },
}

/// Handles retained after a completed attempt. Receipts are not served here.
#[derive(Debug)]
pub struct RenameResult {
    pub outcome: RenameOutcome,
    pub journal: TransactionJournal,
    pub stage: CreatedDirectory,
    pub destination_parent: File,
    /// Caller-supplied ancestry retained throughout the rename. Their presence
    /// alone is not evidence that the chain was qualified or remained named.
    pub ancestry: Vec<File>,
    pub(crate) verified_files: BTreeMap<String, ExclusiveFile>,
}

/// Evidence produced only inside this module after the kernel reports success
/// and the approved final name resolves to the same retained stage identity.
pub(crate) struct ObservedPublication {
    parent: ObjectIdentity,
    stage: ObjectIdentity,
    journal: ObjectIdentity,
    final_name: String,
}

impl ObservedPublication {
    pub(crate) fn matches(
        self,
        parent: ObjectIdentity,
        stage: ObjectIdentity,
        journal: ObjectIdentity,
        binding: &JournalBinding,
    ) -> bool {
        self.parent == parent
            && self.stage == stage
            && self.journal == journal
            && binding.matches_publication_target(parent, &self.final_name)
    }
}

fn observed_publication(
    journal: &TransactionJournal,
    stage: &CreatedDirectory,
    parent: &File,
    name: &str,
) -> Result<ObservedPublication> {
    let parent_id = directory_identity(parent)?;
    let stage_id = directory_identity(stage)?;
    let published = open_checked_child(parent, parent_id, name, false)?;
    ensure!(
        directory_identity(&published)? == stage_id,
        "published identity does not match stage"
    );
    Ok(ObservedPublication {
        parent: ObjectIdentity {
            volume_serial: parent_id.volume_serial,
            file_index: parent_id.file_index,
        },
        stage: ObjectIdentity {
            volume_serial: stage_id.volume_serial,
            file_index: stage_id.file_index,
        },
        journal: journal.approved_journal_identity(),
        final_name: name.to_owned(),
    })
}

#[cfg(test)]
pub(crate) fn synthetic_permit() -> PublicationPermit {
    PublicationPermit(BlockingIoGate::default())
}

enum NativeResult {
    Complete(RenameOutcome),
    Pending(Vec<u64>, Box<IO_STATUS_BLOCK>),
}

fn quarantine_pending<T>(resources: T) {
    std::mem::forget(resources);
}

fn issue_rename(
    journal: &mut TransactionJournal,
    stage: &mut CreatedDirectory,
    parent: &File,
    final_name: &str,
    gate: &BlockingIoGate,
) -> Result<NativeResult> {
    gate.ensure_active()?;
    ensure!(
        valid_component(final_name),
        "invalid final directory component"
    );
    journal.check_publication_binding(parent, stage, final_name)?;
    let name: Vec<u16> = final_name.encode_utf16().collect();
    let bytes = name
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .ok_or_else(|| eyre::eyre!("directory component too large"))?;
    let offset = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName);
    let size = std::mem::size_of::<FILE_RENAME_INFORMATION>()
        .checked_add(bytes)
        .ok_or_else(|| eyre::eyre!("rename buffer too large"))?;
    let mut buffer = vec![0_u64; size.div_ceil(std::mem::size_of::<u64>())];
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    let header = FILE_RENAME_INFORMATION {
        Anonymous: FILE_RENAME_INFORMATION_0 {
            ReplaceIfExists: false,
        },
        RootDirectory: HANDLE(parent.as_raw_handle()),
        FileNameLength: u32::try_from(bytes)?,
        FileName: [0],
    };
    // SAFETY: the u64-backed allocation is aligned and contains the header.
    unsafe { info.write(header) };
    ensure!(
        offset.is_multiple_of(std::mem::size_of::<u16>()),
        "invalid rename layout"
    );
    let target = buffer
        .as_mut_ptr()
        .cast::<u16>()
        .wrapping_add(offset / std::mem::size_of::<u16>());
    // SAFETY: the allocation contains the UTF-16 tail; the source is separate.
    unsafe { std::ptr::copy_nonoverlapping(name.as_ptr(), target, name.len()) };
    let mut io_status = Box::new(IO_STATUS_BLOCK::default());
    journal.check_publication_time()?;
    gate.ensure_active()?;
    // SAFETY: CreatedDirectory originates only from our synchronous create.
    // The worker owns both retained handles and all aligned I/O buffers. A
    // pending response transfers the buffers and handles into quarantine.
    let status = unsafe {
        NtSetInformationFile(
            HANDLE(stage.as_raw_handle()),
            &raw mut *io_status,
            info.cast(),
            u32::try_from(size)?,
            FileRenameInformation,
        )
    };
    if status == STATUS_PENDING {
        return Ok(NativeResult::Pending(buffer, io_status));
    }
    if status.0 == 0 {
        Ok(NativeResult::Complete(
            RenameOutcome::RenamedDurabilityUnconfirmed,
        ))
    } else {
        Ok(NativeResult::Complete(RenameOutcome::Unconfirmed {
            status: u32::from_ne_bytes(status.0.to_ne_bytes()),
        }))
    }
}

struct RetainedDestination {
    parent: File,
    ancestry: Vec<File>,
}

// A directory identity and pre-rename checks do not establish that every
// reopened final file still has its approved identity, hash and stream set.
// Keep the receipt path closed until the handle-relative, deadline-bound final
// re-verification implementation and its independent review are complete.
#[cfg_attr(
    test,
    expect(
        clippy::unnecessary_wraps,
        reason = "production receipt gate stays closed"
    )
)]
fn require_post_rename_file_verification() -> Result<()> {
    #[cfg(not(test))]
    eyre::bail!("post-rename verification is awaiting independent review");
    #[cfg(test)]
    Ok(())
}

async fn run_owned<F>(
    permit: PublicationPermit,
    mut journal: TransactionJournal,
    mut stage: CreatedDirectory,
    destination: RetainedDestination,
    final_name: String,
    deadline: Duration,
    after_issue: F,
) -> Result<RenameResult>
where
    F: FnOnce() + Send + 'static,
{
    ensure!(
        !deadline.is_zero() && deadline <= Duration::from_secs(30),
        "invalid rename deadline"
    );
    ensure!(
        destination.ancestry.len() <= 64,
        "too many retained ancestor handles"
    );
    let expires = std::time::Instant::now()
        .checked_add(deadline)
        .ok_or_else(|| eyre::eyre!("rename deadline overflow"))?;
    let worker_gate = permit.0.clone();
    permit
        .0
        .run(deadline, move || {
            let native = issue_rename(
                &mut journal,
                &mut stage,
                &destination.parent,
                &final_name,
                &worker_gate,
            )?;
            let mut outcome = match native {
                NativeResult::Complete(outcome) => {
                    after_issue();
                    outcome
                }
                NativeResult::Pending(buffer, io_status) => {
                    // Unexpected for a synchronous handle. Keep the I/O buffers,
                    // stage, parent, journal and exclusive lock alive until process
                    // termination; a consumed single-use permit bounds this attempt.
                    quarantine_pending((buffer, io_status, journal, stage, destination));
                    eyre::bail!("pending rename quarantined; inspect after process exit");
                }
            };
            if matches!(outcome, RenameOutcome::Unconfirmed { .. }) {
                journal.mark_publication_uncertain();
            }
            // A timeout/cancellation may have occurred inside the syscall. The
            // worker retains every owned handle until it returns and cannot report
            // a success or receipt through a poisoned gate.
            worker_gate.ensure_active()?;
            let mut verified_files = BTreeMap::new();
            if outcome == RenameOutcome::RenamedDurabilityUnconfirmed {
                let recorded = (|| {
                    let parent_id = directory_identity(&destination.parent)?;
                    let stage_id = directory_identity(&stage)?;
                    super::windows_streams::verify_directory_streams(
                        &destination.parent,
                        parent_id,
                    )?;
                    worker_gate.ensure_active()?;
                    super::windows_streams::verify_directory_streams(&stage, stage_id)?;
                    worker_gate.ensure_active()?;
                    let held =
                        journal.verify_post_rename_files_before(&stage, expires, &worker_gate)?;
                    worker_gate.ensure_active()?;
                    super::windows_streams::verify_directory_streams(
                        &destination.parent,
                        parent_id,
                    )?;
                    let evidence =
                        observed_publication(&journal, &stage, &destination.parent, &final_name)?;
                    require_post_rename_file_verification()?;
                    journal.record_observed_publication(evidence, &worker_gate, expires)?;
                    verified_files = held;
                    Ok::<(), eyre::Report>(())
                })();
                if recorded.is_err() {
                    journal.mark_publication_uncertain();
                    outcome = RenameOutcome::RenamedRecordUnconfirmed;
                }
            }
            worker_gate.ensure_active()?;
            Ok(RenameResult {
                outcome,
                journal,
                stage,
                destination_parent: destination.parent,
                ancestry: destination.ancestry,
                verified_files,
            })
        })
        .await
}

/// Attempt a single no-replace rename, moving the journal, lock, stage and
/// parent into the blocking worker. Timeout or cancellation poisons the gate;
/// the worker retains the objects until the kernel operation finishes.
/// No live permit constructor exists. A successful result persists but does
/// not serve a deterministic receipt or claim power-loss durability.
///
/// # Errors
/// Rejects invalid bindings, expiry, uncertain I/O, timeouts, or a busy gate.
pub async fn rename_with_permit(
    permit: PublicationPermit,
    journal: TransactionJournal,
    stage: CreatedDirectory,
    destination_parent: File,
    final_name: String,
    deadline: Duration,
) -> Result<RenameResult> {
    run_owned(
        permit,
        journal,
        stage,
        RetainedDestination {
            parent: destination_parent,
            ancestry: Vec::new(),
        },
        final_name,
        deadline,
        || {},
    )
    .await
}

/// Like [`rename_with_permit`], retaining caller-qualified ancestry through
/// completion or quarantine. This does not validate or qualify those handles.
/// There is no operational permit constructor; the future qualification gate
/// must prove that the supplied chain is complete, valid and protected.
///
/// # Errors
/// Rejects an empty or overlong ancestry, invalid bindings, expired approval,
/// uncertain I/O, timeouts, or a busy gate.
pub async fn rename_with_permit_and_ancestry(
    permit: PublicationPermit,
    journal: TransactionJournal,
    stage: CreatedDirectory,
    destination_parent: File,
    ancestry: Vec<File>,
    final_name: String,
    deadline: Duration,
) -> Result<RenameResult> {
    ensure!(!ancestry.is_empty(), "qualified ancestry is required");
    run_owned(
        permit,
        journal,
        stage,
        RetainedDestination {
            parent: destination_parent,
            ancestry,
        },
        final_name,
        deadline,
        || {},
    )
    .await
}

/// Reverify an approved stage, record intent and attempt the no-replace rename
/// under one absolute budget. There is no operational `QualifiedCommit`
/// constructor. This coordinator alone does not prove filesystem isolation,
/// peer liveness, a deliverable receipt, or power-loss durability.
///
/// # Errors
/// Returns an error for invalid bindings, expiry, verification or I/O failure,
/// an uncertain pending rename, or a timeout requiring local inspection.
pub async fn commit_qualified_stage(
    input: QualifiedCommit,
    budget: Duration,
) -> Result<RenameResult> {
    commit_qualified_stage_inner(input, budget, || {}, || {}).await
}

async fn commit_qualified_stage_inner<F, G>(
    mut input: QualifiedCommit,
    budget: Duration,
    after_intent: F,
    after_files_closed: G,
) -> Result<RenameResult>
where
    F: FnOnce() + Send + 'static,
    G: FnOnce() + Send + 'static,
{
    ensure!(
        !budget.is_zero() && budget <= Duration::from_secs(30),
        "invalid commit budget"
    );
    ensure!(
        !input.ancestry.is_empty() && input.ancestry.len() <= 64,
        "invalid retained ancestry"
    );
    ensure!(
        valid_component(&input.final_name),
        "invalid final directory component"
    );
    let deadline = std::time::Instant::now()
        .checked_add(budget)
        .ok_or_else(|| eyre::eyre!("commit deadline overflow"))?;
    // Both phases use the permit's same single-flight gate. A competing
    // operation between preflight and rename makes the rename fail closed.
    let gate = input.permit.0.clone();
    let worker_gate = gate.clone();
    let prepared = gate
        .run(budget, move || {
            worker_gate.ensure_active()?;
            let parent_id = directory_identity(&input.destination_parent)?;
            super::windows_streams::verify_directory_streams(&input.destination_parent, parent_id)?;
            worker_gate.ensure_active()?;
            input.journal.check_pre_intent_target(
                &input.destination_parent,
                &input.stage,
                &input.final_name,
            )?;
            worker_gate.ensure_active()?;
            input.journal.prepare_staged_commit_before(
                &input.stage,
                &mut input.files,
                deadline,
                &worker_gate,
            )?;
            after_intent();
            worker_gate.ensure_active()?;
            // Windows directory rename requires the verified children to be closed.
            // The qualification gate must establish the approved same-account trust
            // boundary and exclude other-user mutation during this interval.
            drop(std::mem::take(&mut input.files));
            after_files_closed();
            worker_gate.ensure_active()?;
            ensure!(
                std::time::Instant::now() < deadline,
                "commit deadline expired"
            );
            Ok(input)
        })
        .await?;
    let remaining = deadline
        .checked_duration_since(std::time::Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| eyre::eyre!("commit deadline expired after intent"))?;
    rename_with_permit_and_ancestry(
        prepared.permit,
        prepared.journal,
        prepared.stage,
        prepared.destination_parent,
        prepared.ancestry,
        prepared.final_name,
        remaining,
    )
    .await
}

#[cfg(test)]
pub(crate) async fn synthetic_commit_with_hook<F>(
    input: QualifiedCommit,
    budget: Duration,
    after_intent: F,
) -> Result<RenameResult>
where
    F: FnOnce() + Send + 'static,
{
    commit_qualified_stage_inner(input, budget, after_intent, || {}).await
}

#[cfg(test)]
pub(crate) async fn synthetic_commit_after_close_hook<F>(
    input: QualifiedCommit,
    budget: Duration,
    after_files_closed: F,
) -> Result<RenameResult>
where
    F: FnOnce() + Send + 'static,
{
    commit_qualified_stage_inner(input, budget, || {}, after_files_closed).await
}

#[cfg(test)]
pub(crate) fn synthetic_qualified_commit(
    journal: TransactionJournal,
    files: BTreeMap<String, ExclusiveFile>,
    stage: CreatedDirectory,
    destination_parent: File,
    gate: BlockingIoGate,
    final_name: &str,
) -> QualifiedCommit {
    synthetic_publication_qualification(stage, destination_parent, gate, final_name)
        .bind(journal, files)
}

#[cfg(test)]
pub(crate) fn synthetic_publication_qualification(
    stage: CreatedDirectory,
    destination_parent: File,
    gate: BlockingIoGate,
    final_name: &str,
) -> PublicationQualification {
    let duplicate = destination_parent.try_clone().unwrap();
    PublicationQualification {
        permit: PublicationPermit(gate),
        stage,
        destination_parent,
        ancestry: vec![duplicate],
        final_name: final_name.to_owned(),
    }
}

#[cfg(test)]
pub(crate) async fn synthetic_delayed_rename<F>(
    gate: BlockingIoGate,
    journal: TransactionJournal,
    stage: CreatedDirectory,
    parent_and_ancestry: (File, Vec<File>),
    deadline: Duration,
    after_issue: F,
) -> Result<RenameResult>
where
    F: FnOnce() + Send + 'static,
{
    run_owned(
        PublicationPermit(gate),
        journal,
        stage,
        RetainedDestination {
            parent: parent_and_ancestry.0,
            ancestry: parent_and_ancestry.1,
        },
        "published".to_owned(),
        deadline,
        after_issue,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead as _, Read as _, Write as _};
    use std::os::windows::fs::OpenOptionsExt;
    use std::process::{Command, Stdio};
    use windows::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY,
        FILE_READ_ATTRIBUTES,
    };

    fn exclusive_directory(path: &std::path::Path) -> std::io::Result<File> {
        std::fs::OpenOptions::new()
            .access_mode((FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES).0)
            .share_mode(0)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(path)
    }

    fn exclusive_file(path: &std::path::Path) -> std::io::Result<File> {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .open(path)
    }

    #[test]
    fn pending_quarantine_child() {
        let Some(base) = std::env::var_os("TEAMY_TEST_PENDING_QUARANTINE") else {
            return;
        };
        let base = std::path::PathBuf::from(base);
        let journal = exclusive_file(&base.join("journal.bin")).unwrap();
        let ancestor = exclusive_file(&base.join("ancestor.bin")).unwrap();
        let stage = exclusive_directory(&base.join("stage")).unwrap();
        let parent = exclusive_directory(&base).unwrap();
        // Exercise the exact quarantine helper with synthetic I/O buffers and
        // real exclusively held file and directory handles. No I/O is pending.
        quarantine_pending((
            journal,
            stage,
            parent,
            vec![ancestor],
            vec![0_u64; 8],
            Box::new(IO_STATUS_BLOCK::default()),
        ));
        println!("TEAMY_QUARANTINE_READY");
        std::io::stdout().flush().unwrap();
        let mut byte = [0_u8; 1];
        std::io::stdin().read_exact(&mut byte).unwrap();
    }

    #[test]
    fn pending_quarantine_keeps_handles_until_process_exit() {
        let fixture = tempfile::tempdir().unwrap();
        std::fs::create_dir(fixture.path().join("stage")).unwrap();
        std::fs::write(fixture.path().join("journal.bin"), b"synthetic").unwrap();
        std::fs::write(fixture.path().join("ancestor.bin"), b"synthetic").unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "transfer::windows_publish::tests::pending_quarantine_child",
                "--nocapture",
            ])
            .env("TEAMY_TEST_PENDING_QUARANTINE", fixture.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sent, received) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut signalled = false;
            for line in std::io::BufReader::new(stdout)
                .lines()
                .map_while(std::result::Result::ok)
            {
                if !signalled && line.contains("TEAMY_QUARANTINE_READY") {
                    let _sent = sent.send(());
                    signalled = true;
                }
            }
        });
        if received.recv_timeout(Duration::from_secs(5)).is_err() {
            let _killed = child.kill();
            let _waited = child.wait();
            panic!("synthetic quarantine child did not become ready");
        }
        let _journal_blocked = exclusive_file(&fixture.path().join("journal.bin")).unwrap_err();
        let _ancestor_blocked = exclusive_file(&fixture.path().join("ancestor.bin")).unwrap_err();
        let _stage_blocked = exclusive_directory(&fixture.path().join("stage")).unwrap_err();
        let _parent_blocked = exclusive_directory(fixture.path()).unwrap_err();
        child.stdin.take().unwrap().write_all(b"x").unwrap();
        assert!(child.wait().unwrap().success());
        reader.join().unwrap();
        exclusive_file(&fixture.path().join("journal.bin")).unwrap();
        exclusive_file(&fixture.path().join("ancestor.bin")).unwrap();
        exclusive_directory(&fixture.path().join("stage")).unwrap();
        exclusive_directory(fixture.path()).unwrap();
    }
}
