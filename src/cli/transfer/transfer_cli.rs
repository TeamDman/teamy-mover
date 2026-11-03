use super::receive::TransferReceiveArgs;
use super::send::TransferSendArgs;
use super::validate_manifest::TransferValidateManifestArgs;
use crate::cli::output::CliOutput;
use arbitrary::Arbitrary;
use facet::Facet;
use figue as args;

/// Validate transfer inputs or use the direct sender.
#[derive(Facet, Arbitrary, Debug, PartialEq)]
pub struct TransferArgs {
    #[facet(args::subcommand)]
    pub command: TransferCommand,
}

#[derive(Facet, Arbitrary, Debug, PartialEq)]
#[facet(rename_all = "kebab-case")]
#[repr(u8)]
pub enum TransferCommand {
    /// Verify or send locally approved Linux sources.
    Send(TransferSendArgs),
    /// Validate receiver configuration; live receiving remains gated.
    Receive(TransferReceiveArgs),
    /// Check a locally approved manifest without opening a connection.
    ValidateManifest(TransferValidateManifestArgs),
}

impl TransferArgs {
    /// # Errors
    /// Returns an error for invalid input or disabled send/receive operations.
    pub async fn invoke(self) -> eyre::Result<CliOutput> {
        match self.command {
            TransferCommand::ValidateManifest(args) => args.invoke(),
            TransferCommand::Send(args) => args.invoke().await,
            TransferCommand::Receive(args) => args.invoke().await,
        }
    }
}
