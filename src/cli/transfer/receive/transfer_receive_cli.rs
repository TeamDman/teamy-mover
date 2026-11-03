use arbitrary::Arbitrary;
use facet::Facet;
use figue as args;

/// Receiving is disabled; the process-limit check is diagnostic only.
#[derive(Facet, Arbitrary, Debug, PartialEq)]
#[facet(rename_all = "kebab-case")]
pub struct TransferReceiveArgs {
    /// Configure and read back an empty Windows job; never launch a receiver.
    #[facet(args::named, default)]
    pub check_process_limit: bool,
}

#[cfg(windows)]
#[derive(Facet)]
struct ProcessLimitSummary {
    process_memory_bytes: usize,
    job_configuration_verified: bool,
    process_assigned: bool,
    receiver_started: bool,
}

impl TransferReceiveArgs {
    /// This check runs before runtime startup and grants no transfer capability.
    pub(crate) fn invoke_early(&self) -> eyre::Result<Option<crate::cli::output::CliOutput>> {
        if !self.check_process_limit {
            return Ok(None);
        }
        #[cfg(windows)]
        {
            use crate::transfer::windows_process_limit::PROCESS_MEMORY_BYTES;
            use crate::transfer::windows_process_limit::UnassignedReceiverJob;
            let job = UnassignedReceiverJob::create()?;
            drop(job);
            Ok(Some(crate::cli::output::CliOutput::facet(
                ProcessLimitSummary {
                    process_memory_bytes: PROCESS_MEMORY_BYTES,
                    job_configuration_verified: true,
                    process_assigned: false,
                    receiver_started: false,
                },
                None,
            )))
        }
        #[cfg(not(windows))]
        {
            Err(eyre::eyre!("receiver job-limit check requires Windows"))
        }
    }
}
