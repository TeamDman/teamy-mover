use super::receive::TransferReceiveArgs;
use super::send::TransferSendArgs;
use super::validate_manifest::TransferValidateManifestArgs;
use crate::cli::output::CliOutput;
use arbitrary::Arbitrary;
use facet::Facet;
use figue as args;

/// Validate transfer input. Sending and receiving remain disabled.
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
    /// Check a locally approved manifest without opening a connection.
    ValidateManifest(TransferValidateManifestArgs),
}

impl TransferArgs {
    /// # Errors
    /// Returns an error for invalid input or disabled send/receive operations.
    pub fn invoke(self) -> eyre::Result<CliOutput> {
        match self.command {
            TransferCommand::ValidateManifest(args) => args.invoke(),
            TransferCommand::Send(_) | TransferCommand::Receive(_) => {
                eyre::bail!("transfer is not yet available")
            }
        }
    }
}
