//! Windows job limits for a dedicated one-shot receiver process.
//!
//! Configuring an empty job is only a diagnostic. The live command separately
//! assigns its own process before the async runtime, retains the job, and
//! checks its committed memory. This does not authorize a transfer.

use eyre::Result;
use eyre::ensure;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::FromRawHandle;
use std::os::windows::io::OwnedHandle;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::JobObjects::AssignProcessToJobObject;
use windows::Win32::System::JobObjects::CreateJobObjectW;
use windows::Win32::System::JobObjects::IsProcessInJob;
use windows::Win32::System::JobObjects::JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
use windows::Win32::System::JobObjects::JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
use windows::Win32::System::JobObjects::JOB_OBJECT_LIMIT_PROCESS_MEMORY;
use windows::Win32::System::JobObjects::JOBOBJECT_EXTENDED_LIMIT_INFORMATION;
use windows::Win32::System::JobObjects::JobObjectExtendedLimitInformation;
use windows::Win32::System::JobObjects::QueryInformationJobObject;
use windows::Win32::System::JobObjects::SetInformationJobObject;
use windows::Win32::System::ProcessStatus::{
    GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX,
};
use windows::Win32::System::Threading::GetCurrentProcess;
use windows::core::PCWSTR;

/// The reviewed candidate per-process committed-memory ceiling.
pub const PROCESS_MEMORY_BYTES: usize = 256 * 1024 * 1024;

/// An unnamed, unassigned job whose limits have been read back successfully.
/// This value exposes no process-assignment or resume operation.
#[derive(Debug)]
pub struct UnassignedReceiverJob {
    handle: OwnedHandle,
}

static RECEIVER_JOB: std::sync::OnceLock<UnassignedReceiverJob> = std::sync::OnceLock::new();
static RECEIVER_JOB_INSTALL: std::sync::Mutex<()> = std::sync::Mutex::new(());
static RECEIVER_JOB_VERIFIED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

fn committed_bytes() -> Result<usize> {
    let mut counters = PROCESS_MEMORY_COUNTERS_EX::default();
    let size = u32::try_from(std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>())?;
    counters.cb = size;
    // SAFETY: GetCurrentProcess returns the current process pseudo-handle.
    let process = unsafe { GetCurrentProcess() };
    // SAFETY: the current process handle is valid and the EX buffer is writable.
    unsafe {
        GetProcessMemoryInfo(
            process,
            (&raw mut counters).cast::<PROCESS_MEMORY_COUNTERS>(),
            size,
        )?;
    };
    Ok(counters.PrivateUsage)
}

/// Assign the dedicated receiver process before starting its async runtime.
/// The static retains the kill-on-close job handle for the process lifetime.
/// This limits process commit, not kernel allocations or filesystem safety.
pub(crate) fn apply_current_process_limit() -> Result<()> {
    let _install_guard = RECEIVER_JOB_INSTALL
        .lock()
        .map_err(|_error| eyre::eyre!("receiver job installation unavailable"))?;
    ensure!(
        RECEIVER_JOB.get().is_none(),
        "receiver job is already installed"
    );
    ensure!(
        committed_bytes()? <= PROCESS_MEMORY_BYTES,
        "receiver already exceeds its memory limit"
    );
    let job = UnassignedReceiverJob::create()?;
    let handle = HANDLE(job.handle.as_raw_handle());
    // SAFETY: GetCurrentProcess returns the current process pseudo-handle.
    let process = unsafe { GetCurrentProcess() };
    // SAFETY: the owned job is live and the pseudo-handle identifies this process.
    unsafe { AssignProcessToJobObject(handle, process)? };
    // Once assigned, retain the kill-on-close handle even if verification fails.
    RECEIVER_JOB
        .set(job)
        .map_err(|_job| eyre::eyre!("receiver job installation raced"))?;
    let mut assigned = windows::core::BOOL(0);
    // SAFETY: the retained job and current process are live; assigned is writable.
    unsafe { IsProcessInJob(process, Some(handle), &raw mut assigned)? };
    ensure!(assigned.as_bool(), "receiver process is not in its job");
    ensure!(
        committed_bytes()? <= PROCESS_MEMORY_BYTES,
        "receiver exceeds its memory limit"
    );
    RECEIVER_JOB_VERIFIED.store(true, std::sync::atomic::Ordering::Release);
    Ok(())
}

pub(crate) fn is_current_process_limited() -> bool {
    RECEIVER_JOB_VERIFIED.load(std::sync::atomic::Ordering::Acquire)
}

impl UnassignedReceiverJob {
    /// Create an empty one-process job and verify the requested settings.
    /// Dropping this value closes the job handle. No child is launched.
    ///
    /// # Errors
    /// Returns an error if the job cannot be created, configured or verified.
    pub fn create() -> Result<Self> {
        // SAFETY: Both optional arguments are null; the returned handle is new
        // and is immediately transferred to an owning Rust handle.
        let raw = unsafe { CreateJobObjectW(None, PCWSTR::null())? };
        // SAFETY: `raw` is the unique, valid handle returned by CreateJobObjectW.
        let handle = unsafe { OwnedHandle::from_raw_handle(raw.0) };
        let result = Self { handle };
        let size = u32::try_from(std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())?;
        let mut desired = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        desired.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        desired.BasicLimitInformation.ActiveProcessLimit = 1;
        desired.ProcessMemoryLimit = PROCESS_MEMORY_BYTES;
        // SAFETY: The live handle is an owned job, and the input pointer and
        // size refer to a fully initialized structure for this information class.
        unsafe {
            SetInformationJobObject(
                HANDLE(result.handle.as_raw_handle()),
                JobObjectExtendedLimitInformation,
                (&raw const desired).cast(),
                size,
            )
        }?;
        let mut actual = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        // SAFETY: The output pointer refers to writable storage of the declared
        // size and information class; the job handle remains owned and live.
        unsafe {
            QueryInformationJobObject(
                Some(HANDLE(result.handle.as_raw_handle())),
                JobObjectExtendedLimitInformation,
                (&raw mut actual).cast(),
                size,
                None,
            )
        }?;
        ensure!(
            actual.BasicLimitInformation.LimitFlags == desired.BasicLimitInformation.LimitFlags
                && actual.BasicLimitInformation.ActiveProcessLimit == 1
                && actual.ProcessMemoryLimit == PROCESS_MEMORY_BYTES,
            "Windows job limits did not match the requested configuration"
        );
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_job_limits_are_set_and_verified() {
        let _job = UnassignedReceiverJob::create().expect("configure empty receiver job");
    }

    #[test]
    fn current_process_job_child() {
        if std::env::var_os("TEAMY_TEST_RECEIVER_JOB_CHILD").is_none() {
            return;
        }
        apply_current_process_limit().unwrap();
        assert!(is_current_process_limited());
        assert!(committed_bytes().unwrap() <= PROCESS_MEMORY_BYTES);
    }

    #[test]
    fn job_assignment_is_confined_to_child_process() {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "transfer::windows_process_limit::tests::current_process_job_child",
                "--nocapture",
            ])
            .env("TEAMY_TEST_RECEIVER_JOB_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "child failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(!is_current_process_limited());
    }
}
