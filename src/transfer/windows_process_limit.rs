//! Preparation of an empty Windows job for a possible receiver process.
//!
//! This is not a process launcher or a transfer authorization. No process is
//! assigned, no receiver may use it as a permit, and it is not wired to a CLI.
//! In particular, configuring an empty job does not prove that pre-assignment
//! memory is accounted or that a receiver is subject to a limit.

use eyre::Result;
use eyre::ensure;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::FromRawHandle;
use std::os::windows::io::OwnedHandle;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::JobObjects::CreateJobObjectW;
use windows::Win32::System::JobObjects::JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
use windows::Win32::System::JobObjects::JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
use windows::Win32::System::JobObjects::JOB_OBJECT_LIMIT_PROCESS_MEMORY;
use windows::Win32::System::JobObjects::JOBOBJECT_EXTENDED_LIMIT_INFORMATION;
use windows::Win32::System::JobObjects::JobObjectExtendedLimitInformation;
use windows::Win32::System::JobObjects::QueryInformationJobObject;
use windows::Win32::System::JobObjects::SetInformationJobObject;
use windows::core::PCWSTR;

/// The reviewed candidate per-process committed-memory ceiling.
pub const PROCESS_MEMORY_BYTES: usize = 256 * 1024 * 1024;

/// An unnamed, unassigned job whose limits have been read back successfully.
/// This value exposes no process-assignment or resume operation.
#[derive(Debug)]
pub struct UnassignedReceiverJob {
    handle: OwnedHandle,
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
}
