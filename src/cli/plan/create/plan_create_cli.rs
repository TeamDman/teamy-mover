use crate::cli::output::CliOutput;
use crate::planning;
use arbitrary::Arbitrary;
use facet::Facet;
use figue as args;

#[derive(Facet, Arbitrary, Debug, PartialEq)]
#[facet(rename_all = "kebab-case")]
pub struct PlanCreateArgs {
    /// New plan path, conventionally ending in .plan.json.
    #[facet(args::named)]
    pub plan_file: String,
    /// Short explanation of this plan's purpose.
    #[facet(args::named)]
    pub name: String,
    /// Existing base directory for relative action paths. Defaults to cwd.
    #[facet(args::named)]
    pub base_dir: Option<String>,
    /// Future policy reference; this does not enforce authorization.
    #[facet(args::named)]
    pub policy_reference: Option<String>,
}

impl PlanCreateArgs {
    /// # Errors
    /// Returns an error for invalid metadata, an unavailable base or an
    /// occupied plan path. No source or destination objects are changed.
    pub fn invoke(self) -> eyre::Result<CliOutput> {
        let value = planning::create_plan(
            &self.plan_file,
            &self.name,
            self.base_dir.as_deref(),
            self.policy_reference,
        )?;
        let elapsed_duration_warn_threshold = Some(std::time::Duration::from_secs(3));
        Ok(CliOutput::facet(value, elapsed_duration_warn_threshold))
    }
}
