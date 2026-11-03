use arbitrary::Arbitrary;
use facet::Facet;
use figue as args;

/// Verify approved Linux sources without connecting. Sending remains disabled.
#[derive(Facet, Arbitrary, Debug, PartialEq)]
#[facet(rename_all = "kebab-case")]
pub struct TransferSendArgs {
    /// Verify source files only; never open a connection or send data.
    #[facet(args::named, default)]
    pub verify_only: bool,
    /// Absolute path to the canonical approved manifest.
    #[facet(args::named)]
    pub manifest_file: Option<String>,
    /// Manifest SHA-256 from local approval.
    #[facet(args::named)]
    pub manifest_sha256: Option<String>,
    /// Transaction ID from local approval.
    #[facet(args::named)]
    pub transaction_id: Option<String>,
    /// Absolute path to a local version-one JSON map of source IDs to paths.
    #[facet(args::named)]
    pub source_map: Option<String>,
}

#[cfg(target_os = "linux")]
#[derive(Facet)]
#[facet(deny_unknown_fields)]
struct SourceMap {
    version: u32,
    sources: Vec<SourceEntry>,
}

#[cfg(target_os = "linux")]
#[derive(Facet)]
#[facet(deny_unknown_fields)]
struct SourceEntry {
    id: String,
    path: String,
}

#[cfg(target_os = "linux")]
#[derive(Facet)]
struct VerificationSummary {
    aggregate_bytes: u64,
    file_count: u64,
    verified: bool,
}

impl TransferSendArgs {
    /// Verify locally approved sources only. The operational sender is gated.
    ///
    /// # Errors
    /// Rejects missing approval, unsafe input, mismatched sources or timeouts.
    pub async fn invoke(self) -> eyre::Result<crate::cli::output::CliOutput> {
        if !self.verify_only {
            return Err(eyre::eyre!("transfer is not yet available"));
        }
        #[cfg(target_os = "linux")]
        {
            self.verify_linux().await
        }
        #[cfg(not(target_os = "linux"))]
        {
            std::future::ready(Err(eyre::eyre!(
                "source verification is currently available only on Linux"
            )))
            .await
        }
    }

    #[cfg(target_os = "linux")]
    async fn verify_linux(self) -> eyre::Result<crate::cli::output::CliOutput> {
        use crate::transfer::manifest::{MAX_MANIFEST_BYTES, parse_approved_manifest};
        use crate::transfer::sender::{Source, verify_approved_sources};
        use eyre::ensure;
        use std::collections::BTreeSet;
        use std::io::Read;
        use std::time::{SystemTime, UNIX_EPOCH};

        fn read_bounded(path: &str, limit: usize) -> eyre::Result<Vec<u8>> {
            let file = crate::transfer::source::open_linux(std::path::Path::new(path))?;
            let mut bytes = Vec::new();
            file.take(u64::try_from(limit)? + 1)
                .read_to_end(&mut bytes)?;
            ensure!(bytes.len() <= limit, "input file exceeds limit");
            Ok(bytes)
        }

        let manifest_path = self
            .manifest_file
            .ok_or_else(|| eyre::eyre!("manifest file required"))?;
        let digest = self
            .manifest_sha256
            .ok_or_else(|| eyre::eyre!("manifest digest required"))?;
        let transaction = self
            .transaction_id
            .ok_or_else(|| eyre::eyre!("transaction ID required"))?;
        let map_path = self
            .source_map
            .ok_or_else(|| eyre::eyre!("source map required"))?;
        let manifest_bytes = read_bounded(&manifest_path, MAX_MANIFEST_BYTES)?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let manifest = parse_approved_manifest(&manifest_bytes, &digest, &transaction, now)?;
        let map_bytes = read_bounded(&map_path, MAX_MANIFEST_BYTES)?;
        let map: SourceMap = facet_json::from_slice(&map_bytes)
            .map_err(|_error| eyre::eyre!("invalid source map"))?;
        ensure!(
            map.version == 1 && map.sources.len() == manifest.files().len(),
            "source map does not match approval"
        );
        let mut ids = BTreeSet::new();
        for source in &map.sources {
            ensure!(
                source.path.len() <= 4096
                    && ids.insert(source.id.as_str())
                    && manifest.files().any(|file| file.id() == source.id),
                "source map does not match approval"
            );
        }
        let sources = map
            .sources
            .into_iter()
            .map(|source| Source::open(source.id, std::path::Path::new(&source.path)))
            .collect::<eyre::Result<Vec<_>>>()?;
        verify_approved_sources(&manifest_bytes, &digest, &transaction, sources).await?;
        Ok(crate::cli::output::CliOutput::facet(
            VerificationSummary {
                aggregate_bytes: manifest.aggregate_bytes(),
                file_count: u64::try_from(manifest.files().len())?,
                verified: true,
            },
            Some(std::time::Duration::from_secs(30)),
        ))
    }
}
