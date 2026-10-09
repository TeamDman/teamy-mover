pub mod facet_shape;
pub mod global_args;
pub mod output;
pub mod plan;

use crate::cli::global_args::GlobalArgs;
use crate::cli::output::CliOutput;
use crate::cli::plan::PlanArgs;
use arbitrary::Arbitrary;
use eyre::Context;
use facet::Facet;
use figue::FigueBuiltins;
use figue::{self as args};
use teamy_cancellation::CancellationToken;

/// Prepare reviewable move plans. Dry-run only reads filesystem metadata.
///
/// Creating or adding actions writes plan metadata. There is no command that
/// executes a move, deletes a source, or creates a destination directory.
#[derive(Facet, Arbitrary, Debug)]
pub struct Cli {
    /// Global logging, cancellation, and output options.
    #[facet(flatten)]
    pub global_args: GlobalArgs,

    /// Standard CLI options (help, version, completions).
    #[facet(flatten)]
    #[arbitrary(default)]
    pub builtins: FigueBuiltins,

    /// The command to run.
    #[facet(args::subcommand)]
    pub command: Command,
}

impl PartialEq for Cli {
    fn eq(&self, other: &Self) -> bool {
        // Ignore builtins in comparison since FigueBuiltins doesn't implement PartialEq
        self.global_args == other.global_args && self.command == other.command
    }
}

impl Cli {
    /// # Errors
    ///
    /// This function will return an error if the tokio runtime cannot be built or if the command fails.
    pub fn invoke(self, cancellation_token: CancellationToken) -> eyre::Result<CliOutput> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .wrap_err("Failed to build tokio runtime")?;
        runtime.block_on(async move { self.command.invoke(cancellation_token).await })
    }
}

/// Plan metadata commands. Every operation requires an explicit subcommand.
#[derive(Facet, Arbitrary, Debug, PartialEq)]
#[repr(u8)]
pub enum Command {
    /// Create, inspect, and validate move plans.
    Plan(PlanArgs),
}

impl Command {
    #[must_use]
    pub const fn name(&self) -> &'static str {
        "plan"
    }
    /// # Errors
    ///
    /// This function will return an error if the subcommand fails.
    pub async fn invoke(self, cancellation_token: CancellationToken) -> eyre::Result<CliOutput> {
        cancellation_token.bail_if_cancelled()?;
        match self {
            Command::Plan(args) => args.invoke().await,
        }
    }
}
