use super::action::PlanActionArgs;
use super::create::PlanCreateArgs;
use super::dry_run::PlanDryRunArgs;
use super::list::PlanListArgs;
use super::show::PlanShowArgs;
use crate::cli::output::CliOutput;
use arbitrary::Arbitrary;
use facet::Facet;
use figue as args;

/// Work with versioned JSON move plans.
#[derive(Facet, Arbitrary, Debug, PartialEq)]
pub struct PlanArgs {
    #[facet(args::subcommand)]
    pub command: PlanCommand,
}

#[derive(Facet, Arbitrary, Debug, PartialEq)]
#[facet(rename_all = "kebab-case")]
#[repr(u8)]
pub enum PlanCommand {
    /// Create a new plan file without overwriting an existing file.
    Create(PlanCreateArgs),
    /// Add, inspect, and remove actions within an existing plan.
    Action(PlanActionArgs),
    /// List plan files in one directory without recursive discovery.
    List(PlanListArgs),
    /// Read and show a plan without inspecting its source files.
    Show(PlanShowArgs),
    /// Check ordered future occupancy using read-only metadata calls.
    DryRun(PlanDryRunArgs),
}

impl PlanArgs {
    /// # Errors
    /// Returns an error if the requested plan command fails.
    #[expect(
        clippy::unused_async,
        reason = "template command dispatch uses async invoke methods"
    )]
    pub async fn invoke(self) -> eyre::Result<CliOutput> {
        match self.command {
            PlanCommand::Create(args) => args.invoke(),
            PlanCommand::Action(args) => args.invoke(),
            PlanCommand::List(args) => args.invoke(),
            PlanCommand::Show(args) => args.invoke(),
            PlanCommand::DryRun(args) => args.invoke(),
        }
    }
}
