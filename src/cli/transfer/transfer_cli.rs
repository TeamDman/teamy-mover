use super::receive::TransferReceiveArgs;
use super::send::TransferSendArgs;
use crate::cli::output::CliOutput;
use arbitrary::Arbitrary;
use facet::Facet;
use figue as args;

/// Transfer commands are placeholders and cannot open files or connections.
#[derive(Facet, Arbitrary, Debug, PartialEq)]
pub struct TransferArgs {
    #[facet(args::subcommand)]
    pub command: TransferCommand,
}

#[derive(Facet, Arbitrary, Debug, PartialEq)]
#[facet(rename_all = "kebab-case")]
#[repr(u8)]
pub enum TransferCommand {
    /// Sending is not yet available.
    Send(TransferSendArgs),
    /// Receiving is not yet available.
    Receive(TransferReceiveArgs),
}

impl TransferArgs {
    /// # Errors
    /// Always fails until all operational transfer gates are implemented.
    pub fn invoke(self) -> eyre::Result<CliOutput> {
        eyre::bail!("transfer is not yet available")
    }
}
