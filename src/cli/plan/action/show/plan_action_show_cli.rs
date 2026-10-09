use crate::cli::output::CliOutput;
use crate::planning;
use arbitrary::Arbitrary;
use facet::Facet;
use figue as args;

#[derive(Facet, Arbitrary, Debug, PartialEq)]
#[facet(rename_all = "kebab-case")]
pub struct PlanActionShowArgs {
    /// Existing plan path, @filename, or - for stdin.
    #[facet(args::named)]
    pub plan_file: String,
    /// Positive stable action ID; this is not a position in the action list.
    #[facet(args::named)]
    pub action_id: u64,
}

impl PlanActionShowArgs {
    /// # Errors
    /// Returns an error for an invalid ID, missing action or unreadable input.
    pub fn invoke(self) -> eyre::Result<CliOutput> {
        let value = planning::show_action(&self.plan_file, self.action_id)?;
        let elapsed_duration_warn_threshold =
            crate::elapsed_duration::plan_budget(&self.plan_file, 1, 20);
        Ok(CliOutput::facet(value, elapsed_duration_warn_threshold))
    }
}
