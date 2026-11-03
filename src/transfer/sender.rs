//! Bounded sender using approved source handles.
//!
//! This sends only to a caller-provided authenticated Vox connection. It does
//! not open a socket, create credentials, publish a destination or delete a
//! source. A successful return means bodies were accepted by the peer, not
//! that they were published or are durable.

use super::manifest::ApprovedFile;
use super::manifest::ApprovedManifest;
use super::manifest::parse_approved_manifest;
use super::source::Fingerprint;
use super::source::fingerprint;
use super::verified_stream::FileVerifier;
use super::verified_stream::MAX_CHUNK_BYTES;
use super::vox_transport::BoundedConnection;
use super::wire::TransferState;
use super::wire::TransferWireClient;
use eyre::Result;
use eyre::ensure;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs::File;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncSeekExt;

const OPERATION_DEADLINE: Duration = Duration::from_secs(30);
const SESSION_DEADLINE: Duration = Duration::from_mins(15);

/// A locally selected source handle and its opaque approved file ID.
#[derive(Debug)]
pub struct Source {
    id: String,
    file: File,
}

impl Source {
    /// Open an absolute Linux source path without following symlinks.
    ///
    /// # Errors
    /// Returns an error for unsafe paths, links, non-regular files or I/O failure.
    #[cfg(target_os = "linux")]
    pub fn open(id: String, path: &std::path::Path) -> Result<Self> {
        Ok(Self {
            id,
            file: super::source::open_linux(path)?,
        })
    }

    /// Select an already-open Windows handle. Its path ancestry must have been
    /// independently checked by the caller.
    #[cfg(windows)]
    #[must_use]
    pub fn from_file(id: String, file: File) -> Self {
        Self { id, file }
    }
}

struct CheckedSource {
    id: String,
    file: tokio::fs::File,
    identity: Fingerprint,
}

fn check_expiry(manifest: &ApprovedManifest) -> Result<()> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(now < manifest.expires_unix(), "transfer approval expired");
    Ok(())
}

fn operation_window(manifest: &ApprovedManifest) -> Result<Duration> {
    let expiry = UNIX_EPOCH
        .checked_add(Duration::from_secs(manifest.expires_unix()))
        .ok_or_else(|| eyre::eyre!("invalid transfer expiry"))?;
    let remaining = expiry
        .duration_since(SystemTime::now())
        .map_err(|_error| eyre::eyre!("transfer approval expired"))?;
    ensure!(!remaining.is_zero(), "transfer approval expired");
    Ok(remaining.min(OPERATION_DEADLINE))
}

async fn verify_source(
    file: &mut tokio::fs::File,
    approved: ApprovedFile<'_>,
    manifest: &ApprovedManifest,
) -> Result<()> {
    tokio::time::timeout(
        operation_window(manifest)?,
        file.seek(std::io::SeekFrom::Start(0)),
    )
    .await??;
    let mut verifier = FileVerifier::new(approved, std::io::sink());
    let mut buffer = vec![0u8; MAX_CHUNK_BYTES];
    loop {
        check_expiry(manifest)?;
        let count =
            tokio::time::timeout(operation_window(manifest)?, file.read(&mut buffer)).await??;
        check_expiry(manifest)?;
        if count == 0 {
            break;
        }
        verifier.push(&buffer[..count])?;
    }
    verifier.finish()?;
    tokio::time::timeout(
        operation_window(manifest)?,
        file.seek(std::io::SeekFrom::Start(0)),
    )
    .await??;
    Ok(())
}

async fn send_one(
    client: &TransferWireClient,
    transaction: &str,
    digest: &str,
    approved: ApprovedFile<'_>,
    manifest: &ApprovedManifest,
    mut source: CheckedSource,
) -> Result<()> {
    let (tx, rx) = vox::channel::<Vec<u8>>();
    let (sent, sent_notice) = tokio::sync::oneshot::channel::<()>();
    let upload = async {
        let reply = client.upload(
            transaction.to_owned(),
            digest.to_owned(),
            source.id.clone(),
            rx,
        );
        tokio::pin!(reply);
        let response = tokio::select! {
            result = &mut reply => result,
            result = sent_notice => {
                result.map_err(|_error| eyre::eyre!("source stream ended unexpectedly"))?;
                tokio::time::timeout(operation_window(manifest)?, &mut reply).await?
            }
        };
        response.map_err(|_error| eyre::eyre!("receiver rejected upload"))?;
        Ok::<(), eyre::Report>(())
    };
    let write = async {
        let mut verifier = FileVerifier::new(approved, std::io::sink());
        let mut buffer = vec![0u8; MAX_CHUNK_BYTES];
        loop {
            check_expiry(manifest)?;
            let count =
                tokio::time::timeout(operation_window(manifest)?, source.file.read(&mut buffer))
                    .await??;
            check_expiry(manifest)?;
            if count == 0 {
                break;
            }
            verifier.push(&buffer[..count])?;
            tokio::time::timeout(
                operation_window(manifest)?,
                tx.send(buffer[..count].to_vec()),
            )
            .await??;
        }
        verifier.finish()?;
        let file =
            tokio::time::timeout(operation_window(manifest)?, source.file.into_std()).await?;
        ensure!(
            fingerprint(&file)? == source.identity,
            "source changed while sending"
        );
        tokio::time::timeout(
            operation_window(manifest)?,
            tx.close(vox::Metadata::default()),
        )
        .await??;
        let _ignored = sent.send(());
        Ok::<(), eyre::Report>(())
    };
    tokio::time::timeout(SESSION_DEADLINE, async {
        tokio::try_join!(upload, write)?;
        Ok(())
    })
    .await?
}

async fn send_inner(
    connection: &BoundedConnection,
    manifest: &ApprovedManifest,
    digest: &str,
    sources: Vec<Source>,
) -> Result<()> {
    check_expiry(manifest)?;
    ensure!(
        sources.len() == manifest.files().len(),
        "source set does not match manifest"
    );
    let mut ready = BTreeMap::new();
    let mut identities = BTreeSet::new();
    for source in sources {
        let approved = manifest
            .files()
            .find(|f| f.id() == source.id)
            .ok_or_else(|| eyre::eyre!("source is not approved"))?;
        let identity = fingerprint(&source.file)?;
        ensure!(
            identities.insert((identity.device, identity.object)),
            "duplicate source identity"
        );
        let mut file = tokio::fs::File::from_std(source.file);
        verify_source(&mut file, approved, manifest).await?;
        let file = tokio::time::timeout(operation_window(manifest)?, file.into_std()).await?;
        ensure!(
            fingerprint(&file)? == identity,
            "source changed during verification"
        );
        let file = tokio::fs::File::from_std(file);
        ensure!(
            ready
                .insert(
                    source.id.clone(),
                    CheckedSource {
                        id: source.id,
                        file,
                        identity
                    }
                )
                .is_none(),
            "duplicate source ID"
        );
        check_expiry(manifest)?;
    }
    let client: TransferWireClient =
        tokio::time::timeout(operation_window(manifest)?, connection.open_lane()).await??;
    tokio::time::timeout(
        operation_window(manifest)?,
        client.begin(1, manifest.transaction_id().to_owned(), digest.to_owned()),
    )
    .await?
    .map_err(|_error| eyre::eyre!("receiver rejected begin"))?;
    for approved in manifest.files() {
        check_expiry(manifest)?;
        let source = ready
            .remove(approved.id())
            .ok_or_else(|| eyre::eyre!("missing approved source"))?;
        send_one(
            &client,
            manifest.transaction_id(),
            digest,
            approved,
            manifest,
            source,
        )
        .await?;
    }
    check_expiry(manifest)?;
    let state = tokio::time::timeout(
        operation_window(manifest)?,
        client.status(manifest.transaction_id().to_owned(), digest.to_owned()),
    )
    .await?
    .map_err(|_error| eyre::eyre!("receiver rejected status"))?;
    ensure!(
        state == TransferState::BodiesChecked,
        "receiver did not verify all bodies"
    );
    Ok(())
}

/// Stream one locally approved set over a previously authenticated connection.
/// This function does not attempt commit or source deletion.
///
/// # Errors
/// Returns an error on approval, source, timeout, TLS/Vox or receiver failure.
pub async fn send_prepublication(
    connection: &BoundedConnection,
    manifest_bytes: &[u8],
    manifest_sha256: &str,
    transaction_id: &str,
    sources: Vec<Source>,
) -> Result<()> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let manifest = parse_approved_manifest(manifest_bytes, manifest_sha256, transaction_id, now)?;
    tokio::time::timeout(
        SESSION_DEADLINE,
        send_inner(connection, &manifest, manifest_sha256, sources),
    )
    .await?
}
