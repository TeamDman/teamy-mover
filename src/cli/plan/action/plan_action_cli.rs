use super::add::PlanActionAddArgs;
use super::list::PlanActionListArgs;
use super::remove::PlanActionRemoveArgs;
use super::show::PlanActionShowArgs;
use crate::cli::output::CliOutput;
use arbitrary::Arbitrary;
use facet::Facet;
use figue as args;

/// Edit or inspect actions inside an existing plan. Source files are never changed.
#[derive(Facet, Arbitrary, Debug, PartialEq)]
pub struct PlanActionArgs {
    #[facet(args::subcommand)]
    pub command: PlanActionCommand,
}

#[derive(Facet, Arbitrary, Debug, PartialEq)]
#[facet(rename_all = "kebab-case")]
#[repr(u8)]
pub enum PlanActionCommand {
    /// Append a move action to the plan metadata.
    Add(PlanActionAddArgs),
    /// List the plan's actions in their current order.
    List(PlanActionListArgs),
    /// Show one action by its stable positive ID.
    Show(PlanActionShowArgs),
    /// Remove one action from the plan metadata and retain the prior revision.
    Remove(PlanActionRemoveArgs),
}

impl PlanActionArgs {
    /// # Errors
    /// Returns an error if the selected action command fails.
    pub fn invoke(self) -> eyre::Result<CliOutput> {
        match self.command {
            PlanActionCommand::Add(args) => args.invoke(),
            PlanActionCommand::List(args) => args.invoke(),
            PlanActionCommand::Show(args) => args.invoke(),
            PlanActionCommand::Remove(args) => args.invoke(),
        }
    }
}
