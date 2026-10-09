use crate::cli::output::CliOutput;
use crate::planning;
use arbitrary::Arbitrary;
use facet::Facet;
use figue as args;

#[derive(Facet, Arbitrary, Debug, PartialEq)]
#[facet(rename_all = "kebab-case")]
pub struct PlanShowArgs {
    /// Plan path, @filename, or - to read the plan from stdin.
    #[facet(args::named)]
    pub plan_file: String,
}

impl PlanShowArgs {
    /// # Errors
    /// Returns an error for unreadable or unsupported plan input.
    pub fn invoke(self) -> eyre::Result<CliOutput> {
        let value = planning::read_plan_input(&self.plan_file)?;
        let elapsed_duration_warn_threshold =
            crate::elapsed_duration::plan_budget(&self.plan_file, value.actions.len(), 20);
        Ok(CliOutput::facet(value, elapsed_duration_warn_threshold))
    }
}
