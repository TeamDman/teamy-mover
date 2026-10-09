use crate::cli::output::CliOutput;
use crate::planning;
use arbitrary::Arbitrary;
use facet::Facet;
use figue as args;

#[derive(Facet, Arbitrary, Debug, PartialEq)]
#[facet(rename_all = "kebab-case")]
pub struct PlanListArgs {
    /// Directory containing *.plan.json; default cwd. Does not recurse.
    #[facet(args::named)]
    pub directory: Option<String>,
}

impl PlanListArgs {
    /// # Errors
    /// Returns an error if the directory cannot be read.
    pub fn invoke(self) -> eyre::Result<CliOutput> {
        let value = planning::list_plans(self.directory.as_deref())?;
        let elapsed_duration_warn_threshold = Some(
            std::time::Duration::from_secs(3).saturating_add(
                std::time::Duration::from_millis(20)
                    .saturating_mul(value.len().try_into().unwrap_or(u32::MAX)),
            ),
        );
        Ok(CliOutput::facet(value, elapsed_duration_warn_threshold))
    }
}
