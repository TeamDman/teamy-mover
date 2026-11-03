//! Fail-closed Windows no-replace rename prototype.
//!
//! No operational `PublicationPermit` constructor exists. An independently
//! reviewed gate must establish ancestry, exact contents, token and handle
//! boundaries, filesystem semantics and recovery before any live use.

use super::blocking_io::BlockingIoGate;
use super::manifest::valid_component;
use super::transaction_journal::TransactionJournal;
use super::windows_acl::CreatedDirectory;
use eyre::{Result, ensure};
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

/// An observed rename outcome, never a durability or receipt guarantee.
#[derive(Debug, PartialEq, Eq)]
pub enum RenameOutcome {
    /// Windows reported success; directory and journal durability remain unconfirmed.
    RenamedDurabilityUnconfirmed,
    /// Preserve the objects and reconcile locally; do not retry or issue a receipt.
    Unconfirmed { status: u32 },
}

/// Handles retained after a completed attempt. No receipt is implied.
#[derive(Debug)]
pub struct RenameResult {
    pub outcome: RenameOutcome,
    pub journal: TransactionJournal,
    pub stage: CreatedDirectory,
    pub destination_parent: File,
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

async fn run_owned<F>(
    permit: PublicationPermit,
    mut journal: TransactionJournal,
    mut stage: CreatedDirectory,
    destination_parent: File,
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
    let worker_gate = permit.0.clone();
    permit
        .0
        .run(deadline, move || {
            let native = issue_rename(
                &mut journal,
                &mut stage,
                &destination_parent,
                &final_name,
                &worker_gate,
            )?;
            after_issue();
            let outcome = match native {
                NativeResult::Complete(outcome) => outcome,
                NativeResult::Pending(buffer, io_status) => {
                    // Unexpected for a synchronous handle. Keep the I/O buffers,
                    // stage, parent, journal and exclusive lock alive until process
                    // termination; a consumed single-use permit bounds this attempt.
                    quarantine_pending((buffer, io_status, journal, stage, destination_parent));
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
            Ok(RenameResult {
                outcome,
                journal,
                stage,
                destination_parent,
            })
        })
        .await
}

/// Attempt a single no-replace rename, moving the journal, lock, stage and
/// parent into the blocking worker. Timeout or cancellation poisons the gate;
/// the worker retains the objects until the kernel operation finishes.
/// No live permit constructor exists and no receipt is generated here.
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
        destination_parent,
        final_name,
        deadline,
        || {},
    )
    .await
}

#[cfg(test)]
pub(crate) async fn synthetic_delayed_rename<F>(
    gate: BlockingIoGate,
    journal: TransactionJournal,
    stage: CreatedDirectory,
    parent: File,
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
        parent,
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
        let stage = exclusive_directory(&base.join("stage")).unwrap();
        let parent = exclusive_directory(&base).unwrap();
        // Exercise the exact quarantine helper with synthetic I/O buffers and
        // real exclusively held file and directory handles. No I/O is pending.
        quarantine_pending((
            journal,
            stage,
            parent,
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
        let _stage_blocked = exclusive_directory(&fixture.path().join("stage")).unwrap_err();
        let _parent_blocked = exclusive_directory(fixture.path()).unwrap_err();
        child.stdin.take().unwrap().write_all(b"x").unwrap();
        assert!(child.wait().unwrap().success());
        reader.join().unwrap();
        exclusive_file(&fixture.path().join("journal.bin")).unwrap();
        exclusive_directory(&fixture.path().join("stage")).unwrap();
        exclusive_directory(fixture.path()).unwrap();
    }
}
