use crate::cli::output::CliOutput;
use crate::planning::MoveRequest;
use crate::planning::{self};
use arbitrary::Arbitrary;
use eyre::bail;
use facet::Facet;
use figue as args;

#[derive(Facet, Arbitrary, Debug, PartialEq)]
#[facet(rename_all = "kebab-case")]
pub struct PlanActionAddArgs {
    #[facet(args::named)]
    pub plan_file: String,
    #[facet(args::named)]
    pub source: Option<String>,
    #[facet(args::named)]
    pub destination: Option<String>,
    #[facet(args::named)]
    pub reason: Option<String>,
    /// JSON action: literal JSON, @filename, or - for stdin.
    #[facet(args::named)]
    pub input: Option<String>,
}

impl PlanActionAddArgs {
    /// # Errors
    /// Returns an error for ambiguous arguments, invalid JSON or a failed
    /// metadata update. This never executes the requested move.
    pub fn invoke(self) -> eyre::Result<CliOutput> {
        // Stdin request input waits for the user indefinitely.
        let interactive = self.input.as_deref() == Some("-");
        let request = match (self.source, self.destination, self.reason, self.input) {
            (Some(source), Some(destination), Some(reason), None) => MoveRequest {
                source,
                destination,
                reason,
            },
            (None, None, None, Some(input)) => planning::read_request(&input)?,
            _ => bail!(
                "supply --source, --destination, and --reason together, or supply only --input"
            ),
        };
        let value = planning::add_move(&self.plan_file, request)?;
        let elapsed_duration_warn_threshold = if interactive {
            None
        } else {
            crate::elapsed_duration::plan_budget(&self.plan_file, value.actions.len(), 20)
        };
        Ok(CliOutput::facet(value, elapsed_duration_warn_threshold))
    }
}
