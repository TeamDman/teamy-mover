use crate::cli::output::CliOutput;
use crate::planning;
use arbitrary::Arbitrary;
use facet::Facet;
use figue as args;

#[derive(Facet, Arbitrary, Debug, PartialEq)]
#[facet(rename_all = "kebab-case")]
pub struct PlanActionRemoveArgs {
    /// Literal path to the existing plan to update.
    #[facet(args::named)]
    pub plan_file: String,
    /// Positive stable action ID to remove from metadata only.
    #[facet(args::named)]
    pub action_id: u64,
}

impl PlanActionRemoveArgs {
    /// # Errors
    /// Returns an error for an invalid/missing action or failed metadata write.
    /// Source and destination files are never removed or otherwise changed.
    pub fn invoke(self) -> eyre::Result<CliOutput> {
        let value = planning::remove_action(&self.plan_file, self.action_id)?;
        let elapsed_duration_warn_threshold =
            crate::elapsed_duration::plan_budget(&self.plan_file, value.actions.len(), 20);
        Ok(CliOutput::facet(value, elapsed_duration_warn_threshold))
    }
}
