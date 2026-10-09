use crate::cli::output::CliOutput;
use crate::planning;
use arbitrary::Arbitrary;
use facet::Facet;
use figue as args;

#[derive(Facet, Arbitrary, Debug, PartialEq)]
#[facet(rename_all = "kebab-case")]
pub struct PlanActionListArgs {
    /// Existing plan path, @filename, or - for stdin.
    #[facet(args::named)]
    pub plan_file: String,
}

impl PlanActionListArgs {
    /// # Errors
    /// Returns an error for invalid or unreadable plan input.
    pub fn invoke(self) -> eyre::Result<CliOutput> {
        let value = planning::list_actions(&self.plan_file)?;
        let elapsed_duration_warn_threshold =
            crate::elapsed_duration::plan_budget(&self.plan_file, value.len(), 20);
        Ok(CliOutput::facet(value, elapsed_duration_warn_threshold))
    }
}
