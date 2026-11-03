//! Strict parsing of the version-one approved transfer manifest.
//!
//! The digest and transaction ID passed here must come from protected local
//! approval configuration, never from the peer supplying the manifest.

use eyre::Result;
use eyre::bail;
use eyre::ensure;
use facet::Facet;
use sha2::Digest;
use sha2::Sha256;
use std::collections::HashSet;

/// Maximum accepted canonical manifest size in bytes.
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_FILES: usize = 16;
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 128 * 1024 * 1024;
const MAX_SAFE_JSON_INTEGER: u64 = (1_u64 << 53) - 1;

// Field order is lexicographic. With the restricted string alphabet and integer
// ranges checked below, facet_json's compact encoding is the RFC 8785 encoding
// for this schema. Comparing bytes rejects whitespace, escapes and key reordering.
#[derive(Clone, Debug, Facet)]
#[facet(deny_unknown_fields)]
struct Manifest {
    aggregate_bytes: u64,
    expires_unix: u64,
    file_count: u32,
    files: Vec<ManifestFile>,
    transaction_id: String,
    version: u32,
}

#[derive(Clone, Debug, Facet)]
#[facet(deny_unknown_fields)]
struct ManifestFile {
    id: String,
    name: String,
    sha256: String,
    size: u64,
}

/// A manifest checked against locally supplied approval data.
/// Its contents cannot be modified after validation.
#[derive(Clone, Debug)]
pub struct ApprovedManifest(Manifest);

/// A read-only view of an approved file entry.
#[derive(Clone, Copy, Debug)]
pub struct ApprovedFile<'a>(&'a ManifestFile);

impl ApprovedManifest {
    #[must_use]
    pub fn transaction_id(&self) -> &str {
        &self.0.transaction_id
    }

    #[must_use]
    pub const fn expires_unix(&self) -> u64 {
        self.0.expires_unix
    }

    #[must_use]
    pub const fn aggregate_bytes(&self) -> u64 {
        self.0.aggregate_bytes
    }

    pub fn files(&self) -> impl ExactSizeIterator<Item = ApprovedFile<'_>> {
        self.0.files.iter().map(ApprovedFile)
    }
}

impl<'a> ApprovedFile<'a> {
    #[must_use]
    pub fn id(self) -> &'a str {
        &self.0.id
    }

    #[must_use]
    pub fn name(self) -> &'a str {
        &self.0.name
    }

    #[must_use]
    pub fn sha256(self) -> &'a str {
        &self.0.sha256
    }

    #[must_use]
    pub const fn size(self) -> u64 {
        self.0.size
    }
}

fn lowercase_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Check the conservative, portable filename subset used by version one.
#[must_use]
pub fn valid_component(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 128
        || !bytes[0].is_ascii_alphanumeric()
        || bytes.last() == Some(&b'.')
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return false;
    }
    let basename = value
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    if matches!(basename.as_str(), "CON" | "PRN" | "AUX" | "NUL") {
        return false;
    }
    let suffix = basename
        .strip_prefix("COM")
        .or_else(|| basename.strip_prefix("LPT"));
    !matches!(suffix, Some(s) if s.len() == 1 && matches!(s.as_bytes()[0], b'1'..=b'9'))
}

fn validate(manifest: &Manifest, expected_id: &str, now_unix: Option<u64>) -> Result<()> {
    ensure!(manifest.version == 1, "unsupported manifest version");
    ensure!(
        lowercase_hex(expected_id, 32),
        "invalid approved transaction ID"
    );
    ensure!(
        manifest.transaction_id == expected_id,
        "transaction ID does not match approval"
    );
    ensure!(
        manifest.expires_unix <= MAX_SAFE_JSON_INTEGER,
        "expiry outside safe integer range"
    );
    ensure!(manifest.expires_unix > 0, "invalid manifest expiry");
    if let Some(now) = now_unix {
        ensure!(manifest.expires_unix > now, "manifest has expired");
    }
    ensure!(
        (1..=MAX_FILES).contains(&manifest.files.len()),
        "invalid file count"
    );
    ensure!(
        usize::try_from(manifest.file_count)? == manifest.files.len(),
        "file count mismatch"
    );
    ensure!(
        manifest.aggregate_bytes <= MAX_TOTAL_BYTES,
        "aggregate limit exceeded"
    );

    let mut ids = HashSet::new();
    let mut names = HashSet::new();
    let mut total = 0_u64;
    for file in &manifest.files {
        ensure!(
            (1..=32).contains(&file.id.len())
                && file.id.bytes().all(|byte| byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'_' | b'-')),
            "invalid file ID"
        );
        ensure!(ids.insert(&file.id), "duplicate file ID");
        ensure!(valid_component(&file.name), "invalid filename");
        ensure!(
            names.insert(file.name.to_ascii_lowercase()),
            "colliding filenames"
        );
        ensure!(lowercase_hex(&file.sha256, 64), "invalid file digest");
        ensure!(file.size <= MAX_FILE_BYTES, "file limit exceeded");
        total = total
            .checked_add(file.size)
            .ok_or_else(|| eyre::eyre!("aggregate overflow"))?;
    }
    ensure!(total == manifest.aggregate_bytes, "aggregate size mismatch");
    Ok(())
}

/// Parse canonical JSON and bind it to a locally approved digest and ID.
///
/// This validates manifest metadata only. It does not validate source handles,
/// authorize a transfer, access the network, or establish an execution gate.
///
/// # Errors
/// Returns an error for noncanonical, invalid, expired, or unapproved input.
pub fn parse_approved_manifest(
    bytes: &[u8],
    expected_sha256: &str,
    expected_transaction_id: &str,
    now_unix: u64,
) -> Result<ApprovedManifest> {
    parse_manifest_inner(
        bytes,
        expected_sha256,
        expected_transaction_id,
        Some(now_unix),
    )
}

/// Parse a locally approved manifest for read-only inspection without treating
/// its expired authorization as permission for a new transfer or receipt.
#[cfg(windows)]
pub(crate) fn parse_for_local_inspection(
    bytes: &[u8],
    expected_sha256: &str,
    expected_transaction_id: &str,
) -> Result<ApprovedManifest> {
    parse_manifest_inner(bytes, expected_sha256, expected_transaction_id, None)
}

fn parse_manifest_inner(
    bytes: &[u8],
    expected_sha256: &str,
    expected_transaction_id: &str,
    now_unix: Option<u64>,
) -> Result<ApprovedManifest> {
    ensure!(
        bytes.len() <= MAX_MANIFEST_BYTES,
        "manifest exceeds byte limit"
    );
    ensure!(
        lowercase_hex(expected_sha256, 64),
        "invalid approved manifest digest"
    );
    let digest = format!("{:x}", Sha256::digest(bytes));
    ensure!(
        digest == expected_sha256,
        "manifest digest does not match approval"
    );
    let manifest: Manifest =
        facet_json::from_slice(bytes).map_err(|_error| eyre::eyre!("invalid manifest JSON"))?;
    validate(&manifest, expected_transaction_id, now_unix)?;
    if facet_json::to_string(&manifest)?.as_bytes() != bytes {
        bail!("manifest is not canonical JSON");
    }
    Ok(ApprovedManifest(manifest))
}
