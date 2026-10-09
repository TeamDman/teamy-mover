use crate::cli::output::CliOutput;
use crate::planning;
use arbitrary::Arbitrary;
use facet::Facet;
use figue as args;

#[derive(Facet, Arbitrary, Debug, PartialEq)]
#[facet(rename_all = "kebab-case")]
pub struct PlanDryRunArgs {
    /// Plan path, @filename, or - to read the plan from stdin.
    #[facet(args::named)]
    pub plan_file: String,
}

impl PlanDryRunArgs {
    /// # Errors
    /// Returns an error if the plan cannot be read. A completed inspection
    /// emits a structured report, including any conflicts, and returns success.
    pub fn invoke(self) -> eyre::Result<CliOutput> {
        let report = planning::dry_run_input(&self.plan_file)?;
        if !report.ready {
            tracing::warn!(
                invalid_actions = report.actions.iter().filter(|action| !action.valid).count(),
                "dry-run completed with planning conflicts; inspect ready and action issues"
            );
        }
        let value = report;
        let elapsed_duration_warn_threshold = crate::elapsed_duration::plan_budget(
            &self.plan_file,
            value.actions.len().saturating_mul(value.actions.len()),
            1,
        );
        Ok(CliOutput::facet(value, elapsed_duration_warn_threshold))
    }
}
