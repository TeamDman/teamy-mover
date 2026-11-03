use crate::cli::output::CliOutput;
use crate::transfer::manifest::MAX_MANIFEST_BYTES;
use crate::transfer::manifest::parse_approved_manifest;
use arbitrary::Arbitrary;
use eyre::ensure;
use facet::Facet;
use figue as args;
use std::io::Read;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

/// Check manifest bytes against an independently supplied approval digest and ID.
#[derive(Facet, Arbitrary, Debug, PartialEq)]
#[facet(rename_all = "kebab-case")]
pub struct TransferValidateManifestArgs {
    /// Path to the canonical manifest file.
    #[facet(args::named)]
    pub manifest_file: String,
    /// Expected lowercase SHA-256 from local approval.
    #[facet(args::named)]
    pub manifest_sha256: String,
    /// Expected transaction ID from local approval.
    #[facet(args::named)]
    pub transaction_id: String,
}

#[derive(Facet)]
struct ManifestSummary {
    aggregate_bytes: u64,
    expires_unix: u64,
    file_count: u64,
    valid: bool,
}

impl TransferValidateManifestArgs {
    /// Validate only; this does not authorize a transfer or create files.
    ///
    /// # Errors
    /// Returns an error for invalid, expired, mismatched or unreadable input.
    pub fn invoke(self) -> eyre::Result<CliOutput> {
        #[cfg(target_os = "linux")]
        let file = crate::transfer::source::open_linux(std::path::Path::new(&self.manifest_file))?;
        #[cfg(not(target_os = "linux"))]
        let file = std::fs::File::open(&self.manifest_file)?;
        ensure!(
            file.metadata()?.is_file(),
            "manifest must be a regular file"
        );
        let mut bytes = Vec::new();
        file.take(u64::try_from(MAX_MANIFEST_BYTES)? + 1)
            .read_to_end(&mut bytes)?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let manifest =
            parse_approved_manifest(&bytes, &self.manifest_sha256, &self.transaction_id, now)?;
        let summary = ManifestSummary {
            aggregate_bytes: manifest.aggregate_bytes(),
            expires_unix: manifest.expires_unix(),
            file_count: u64::try_from(manifest.files().len())?,
            valid: true,
        };
        Ok(CliOutput::facet(
            summary,
            Some(std::time::Duration::from_secs(3)),
        ))
    }
}
