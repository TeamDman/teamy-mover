//! Journal-backed, pre-publication receiver.
//!
//! Operational construction is intentionally blocked: a `StagingPermit` cannot
//! yet be created outside this module. Windows staging isolation and publication
//! remain unresolved. No listener, path creation, source deletion or publication
//! is implemented here.

use super::journal::JournalApproval;
use super::manifest::ApprovedManifest;
use super::manifest::parse_approved_manifest;
use super::tls::AuthenticatedServer;
use super::transaction_journal::TransactionJournal;
use super::verified_stream::FileVerifier;
use super::vox_transport::BoundedConnection;
use super::vox_transport::{self};
use super::windows_lock::ExclusiveFile;
use super::wire::TransferError;
use super::wire::TransferState;
use super::wire::TransferWire;
use super::wire::TransferWireDispatcher;
use eyre::Result;
use eyre::ensure;
use std::collections::BTreeMap;
use std::io::Seek;
use std::io::SeekFrom;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::sync::Mutex;

const MAX_SESSION: Duration = Duration::from_mins(15);
const MAX_IDLE: Duration = Duration::from_secs(30);

/// Reserved for a future reviewed, platform-verified staging implementation.
/// There is deliberately no public way to construct this permit.
#[derive(Debug)]
pub struct StagingPermit(());

struct State {
    journal: TransactionJournal,
    manifest: ApprovedManifest,
    digest: String,
    files: BTreeMap<String, ExclusiveFile>,
    begun: bool,
    in_flight_or_failed: bool,
    deadline: tokio::time::Instant,
}

/// A one-connection receiver that cannot publish or delete files.
#[derive(Clone)]
pub struct Receiver {
    state: Arc<Mutex<State>>,
    started: Arc<AtomicBool>,
}

impl std::fmt::Debug for Receiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Receiver").finish_non_exhaustive()
    }
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn check(state: &State, transaction: &str, digest: &str) -> std::result::Result<(), TransferError> {
    if state.in_flight_or_failed {
        return Err(TransferError::Failed);
    }
    if tokio::time::Instant::now() >= state.deadline
        || now().map_or(true, |time| time >= state.manifest.expires_unix())
    {
        return Err(TransferError::Expired);
    }
    if transaction != state.manifest.transaction_id() || digest != state.digest {
        return Err(TransferError::Rejected);
    }
    Ok(())
}

impl Receiver {
    /// Prepare pre-existing exclusively held files and journal their claims.
    /// This is unavailable until a reviewed staging permit exists.
    ///
    /// # Errors
    /// Rejects mismatched approval, missing files, unsafe claims and I/O errors.
    pub fn prepare(
        _permit: StagingPermit,
        mut journal: TransactionJournal,
        approval: &JournalApproval<'_>,
        mut files: BTreeMap<String, ExclusiveFile>,
    ) -> Result<Self> {
        ensure!(
            journal.matches_approval(approval)?,
            "journal approval mismatch"
        );
        let current = now()?;
        let manifest = parse_approved_manifest(
            approval.manifest_bytes,
            approval.manifest_sha256,
            approval.transaction_id,
            current,
        )?;
        ensure!(files.len() == manifest.files().len(), "file set mismatch");
        for approved in manifest.files() {
            let file = files
                .get_mut(approved.id())
                .ok_or_else(|| eyre::eyre!("missing approved file"))?;
            if journal.has_observation(approved.id()) {
                file.verify()?;
                journal.verify_file(approved.id(), file.file_mut(), current)?;
            } else {
                journal.claim_empty_file(approved.id(), file, current)?;
            }
        }
        Ok(Self {
            state: Arc::new(Mutex::new(State {
                journal,
                manifest,
                digest: approval.manifest_sha256.to_owned(),
                files,
                begun: false,
                in_flight_or_failed: false,
                deadline: tokio::time::Instant::now() + MAX_SESSION,
            })),
            started: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Bind the service to one already authenticated TLS stream. The peer pin
    /// must match the journal; no listening socket is created.
    ///
    /// # Errors
    /// Rejects mismatched client certificates, repeated starts or Vox failure.
    pub async fn establish<S>(self, stream: AuthenticatedServer<S>) -> Result<BoundedConnection>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (client_matches, server_matches) = {
            let state = self.state.lock().await;
            check(&state, state.manifest.transaction_id(), &state.digest)
                .map_err(|_error| eyre::eyre!("receiver session unavailable"))?;
            (
                state.journal.matches_client_pin(&stream.client_pin()),
                state.journal.matches_server_pin(&stream.server_pin()),
            )
        };
        ensure!(client_matches, "client certificate does not match journal");
        ensure!(server_matches, "server certificate does not match journal");
        ensure!(
            self.started
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok(),
            "receiver connection already started"
        );
        vox_transport::establish_server(stream, TransferWireDispatcher::new(self)).await
    }
}

impl TransferWire for Receiver {
    async fn begin(
        &self,
        version: u32,
        transaction_id: String,
        manifest_sha256: String,
    ) -> std::result::Result<(), TransferError> {
        let mut state = self
            .state
            .try_lock()
            .map_err(|_error| TransferError::NotReady)?;
        check(&state, &transaction_id, &manifest_sha256)?;
        if version != 1 {
            return Err(TransferError::Rejected);
        }
        state.begun = true;
        Ok(())
    }

    async fn upload(
        &self,
        transaction_id: String,
        manifest_sha256: String,
        file_id: String,
        mut chunks: vox::Rx<Vec<u8>>,
    ) -> std::result::Result<(), TransferError> {
        let mut state = self
            .state
            .try_lock()
            .map_err(|_error| TransferError::NotReady)?;
        check(&state, &transaction_id, &manifest_sha256)?;
        if !state.begun {
            return Err(TransferError::NotReady);
        }
        if !state.files.contains_key(&file_id) || !state.manifest.files().any(|f| f.id() == file_id)
        {
            return Err(TransferError::Rejected);
        }
        // Cancellation or any failure leaves this flag set and partial data
        // untouched. A new process must inspect/recover the journal explicitly.
        state.in_flight_or_failed = true;
        let result = receive_body(&mut state, &file_id, &mut chunks).await;
        if result.is_ok() {
            state.in_flight_or_failed = false;
        }
        result.map_err(|_error| TransferError::Failed)
    }

    async fn status(
        &self,
        transaction_id: String,
        manifest_sha256: String,
    ) -> std::result::Result<TransferState, TransferError> {
        let state = self
            .state
            .try_lock()
            .map_err(|_error| TransferError::NotReady)?;
        check(&state, &transaction_id, &manifest_sha256)?;
        if !state.begun {
            return Ok(TransferState::AwaitingBegin);
        }
        if state
            .manifest
            .files()
            .all(|file| state.journal.has_observation(file.id()))
        {
            Ok(TransferState::BodiesChecked)
        } else {
            Ok(TransferState::Receiving)
        }
    }

    async fn commit(
        &self,
        transaction_id: String,
        manifest_sha256: String,
    ) -> std::result::Result<(), TransferError> {
        let state = self
            .state
            .try_lock()
            .map_err(|_error| TransferError::NotReady)?;
        check(&state, &transaction_id, &manifest_sha256)?;
        Err(TransferError::NotReady)
    }
}

async fn receive_body(state: &mut State, id: &str, chunks: &mut vox::Rx<Vec<u8>>) -> Result<()> {
    let completed = state.journal.has_observation(id);
    let approved = state
        .manifest
        .files()
        .find(|file| file.id() == id)
        .ok_or_else(|| eyre::eyre!("unknown file"))?;
    let file = state
        .files
        .get_mut(id)
        .ok_or_else(|| eyre::eyre!("missing file"))?;
    file.verify()?;
    let output = file.file_mut();
    if !completed {
        ensure!(
            output.metadata()?.len() == 0,
            "partial file requires inspection"
        );
        output.seek(SeekFrom::Start(0))?;
    }
    // A completed duplicate is verified against the manifest and then against
    // the retained file; it is never overwritten.
    let mut verifier: FileVerifier<Box<dyn std::io::Write + Send + '_>> = if completed {
        FileVerifier::new(approved, Box::new(std::io::sink()))
    } else {
        FileVerifier::new(approved, Box::new(&mut *output))
    };
    loop {
        let current = now()?;
        ensure!(current < state.manifest.expires_unix(), "approval expired");
        let remaining = state
            .deadline
            .checked_duration_since(tokio::time::Instant::now())
            .ok_or_else(|| eyre::eyre!("session expired"))?;
        let expiry = UNIX_EPOCH
            .checked_add(Duration::from_secs(state.manifest.expires_unix()))
            .ok_or_else(|| eyre::eyre!("invalid approval expiry"))?;
        let approval_remaining = expiry
            .duration_since(SystemTime::now())
            .map_err(|_error| eyre::eyre!("approval expired"))?;
        let item = tokio::time::timeout(
            remaining.min(MAX_IDLE).min(approval_remaining),
            chunks.recv(),
        )
        .await??;
        match item {
            Some(chunk) => verifier.push(chunk.get())?,
            None => break,
        }
    }
    verifier.finish()?;
    ensure!(
        tokio::time::Instant::now() < state.deadline,
        "session expired"
    );
    let current = now()?;
    state.journal.verify_file(id, output, current)?;
    file.verify()?;
    ensure!(
        tokio::time::Instant::now() < state.deadline && now()? < state.manifest.expires_unix(),
        "session expired"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transfer::journal::ObjectIdentity;
    use crate::transfer::sender::Source;
    use crate::transfer::sender::send_prepublication;
    use crate::transfer::tls::ClientEndpoint;
    use crate::transfer::tls::ServerEndpoint;
    use crate::transfer::windows_lock::regular_file_identity;
    use rcgen::BasicConstraints;
    use rcgen::CertificateParams;
    use rcgen::ExtendedKeyUsagePurpose;
    use rcgen::IsCa;
    use rcgen::Issuer;
    use rcgen::KeyPair;
    use rcgen::KeyUsagePurpose;
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::PrivateKeyDer;
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use rustls::pki_types::ServerName;
    use sha2::Digest;
    use sha2::Sha256;
    use std::fs::File;
    use std::io::Read as _;

    const ID: &str = "0123456789abcdef0123456789abcdef";

    fn certificates() -> (ClientEndpoint, ServerEndpoint, String, String) {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        ca_params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);
        let issue = |names: Vec<String>,
                     usage: ExtendedKeyUsagePurpose|
         -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
            let mut params = CertificateParams::new(names).unwrap();
            params.extended_key_usages.push(usage);
            params.key_usages.push(KeyUsagePurpose::DigitalSignature);
            let key = KeyPair::generate().unwrap();
            let cert = params.signed_by(&key, &issuer).unwrap();
            (
                cert.der().clone(),
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
        };
        let (server_cert, server_key) = issue(
            vec!["100.64.0.1".into()],
            ExtendedKeyUsagePurpose::ServerAuth,
        );
        let (client_cert, client_key) = issue(Vec::new(), ExtendedKeyUsagePurpose::ClientAuth);
        let server_pin: [u8; 32] = Sha256::digest(server_cert.as_ref()).into();
        let server_hex = format!("{:x}", Sha256::digest(server_cert.as_ref()));
        let client_pin: [u8; 32] = Sha256::digest(client_cert.as_ref()).into();
        let client_hex = format!("{:x}", Sha256::digest(client_cert.as_ref()));
        let root = ca_cert.der().clone();
        let client = ClientEndpoint::new(
            vec![root.clone()],
            vec![client_cert],
            client_key,
            ServerName::try_from("100.64.0.1".to_owned()).unwrap(),
            server_pin,
        )
        .unwrap();
        let server =
            ServerEndpoint::new(vec![root], vec![server_cert], server_key, client_pin).unwrap();
        (client, server, client_hex, server_hex)
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        source: std::path::PathBuf,
        raw: String,
        digest: String,
        receiver: Receiver,
        client: ClientEndpoint,
        server: ServerEndpoint,
    }

    fn fixture(wrong_journal_pin: bool, wrong_server_pin: bool) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let target = dir.path().join("stage-file");
        let journal_path = dir.path().join("journal");
        std::fs::write(&source, b"hello").unwrap();
        File::create(&target).unwrap();
        File::create(&journal_path).unwrap();
        let target_id = regular_file_identity(&File::open(&target).unwrap()).unwrap();
        let journal_id = regular_file_identity(&File::open(&journal_path).unwrap()).unwrap();
        let hash = format!("{:x}", Sha256::digest(b"hello"));
        let expiry = now().unwrap() + 600;
        let raw = format!(
            r#"{{"aggregate_bytes":5,"expires_unix":{expiry},"file_count":1,"files":[{{"id":"one","name":"a.bin","sha256":"{hash}","size":5}}],"transaction_id":"{ID}","version":1}}"#
        );
        let digest = format!("{:x}", Sha256::digest(raw.as_bytes()));
        let (client, server, client_pin, server_pin) = certificates();
        let wrong = "0".repeat(64);
        let pin = if wrong_journal_pin {
            &wrong
        } else {
            &client_pin
        };
        let volume = journal_id.volume_serial;
        let approval = JournalApproval {
            manifest_bytes: raw.as_bytes(),
            manifest_sha256: &digest,
            transaction_id: ID,
            client_pin: pin,
            server_pin: if wrong_server_pin {
                &wrong
            } else {
                &server_pin
            },
            destination_parent: ObjectIdentity {
                volume_serial: volume,
                file_index: journal_id.file_index ^ (1 << 63),
            },
            stage_directory: ObjectIdentity {
                volume_serial: volume,
                file_index: journal_id.file_index ^ (1 << 62),
            },
            journal_file: ObjectIdentity {
                volume_serial: volume,
                file_index: journal_id.file_index,
            },
            final_name: "synthetic",
            now_unix: now().unwrap(),
        };
        let journal = TransactionJournal::initialize(
            ExclusiveFile::acquire(&journal_path, journal_id).unwrap(),
            &approval,
        )
        .unwrap();
        let mut files = BTreeMap::new();
        files.insert(
            "one".to_owned(),
            ExclusiveFile::acquire(&target, target_id).unwrap(),
        );
        let receiver = Receiver::prepare(StagingPermit(()), journal, &approval, files).unwrap();
        Fixture {
            _dir: dir,
            source,
            raw,
            digest,
            receiver,
            client,
            server,
        }
    }

    #[tokio::test]
    async fn sends_synthetic_data_through_pinned_tls_into_real_journal() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let fixture = fixture(false, false);
            let control = fixture.receiver.clone();
            let (left, right) = tokio::io::duplex(128 * 1024);
            let (client_tls, server_tls) =
                tokio::join!(fixture.client.connect(left), fixture.server.accept(right));
            let (client_conn, server_conn) = tokio::join!(
                vox_transport::establish_client(client_tls.unwrap()),
                fixture.receiver.establish(server_tls.unwrap())
            );
            let client_conn = client_conn.unwrap();
            let _server_conn = server_conn.unwrap();
            let sources = vec![Source::from_file(
                "one".into(),
                File::open(&fixture.source).unwrap(),
            )];
            send_prepublication(
                &client_conn,
                fixture.raw.as_bytes(),
                &fixture.digest,
                ID,
                sources,
            )
            .await
            .unwrap();
            let mut state = control.state.lock().await;
            assert!(state.journal.has_observation("one"));
            let mut bytes = Vec::new();
            let file = state.files.get_mut("one").unwrap().file_mut();
            file.seek(SeekFrom::Start(0)).unwrap();
            file.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, b"hello");
            drop(state);
            assert!(matches!(
                control.commit(ID.into(), fixture.digest.clone()).await,
                Err(TransferError::NotReady)
            ));
            assert_eq!(std::fs::read(&fixture.source).unwrap(), b"hello");
        })
        .await
        .expect("receiver integration test timed out");
    }

    #[tokio::test]
    async fn rejects_tls_peer_not_bound_to_journal() {
        let fixture = fixture(true, false);
        let (left, right) = tokio::io::duplex(128 * 1024);
        let (client_tls, server_tls) =
            tokio::join!(fixture.client.connect(left), fixture.server.accept(right));
        let _client_tls = client_tls.unwrap();
        let error = fixture
            .receiver
            .establish(server_tls.unwrap())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("does not match journal"));
        assert_eq!(std::fs::read(&fixture.source).unwrap(), b"hello");
    }

    #[tokio::test]
    async fn rejects_tls_server_not_bound_to_journal() {
        let fixture = fixture(false, true);
        let (left, right) = tokio::io::duplex(128 * 1024);
        let (client_tls, server_tls) =
            tokio::join!(fixture.client.connect(left), fixture.server.accept(right));
        let _client_tls = client_tls.unwrap();
        let error = fixture
            .receiver
            .establish(server_tls.unwrap())
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("server certificate does not match journal")
        );
    }

    #[tokio::test]
    async fn rejects_incomplete_upload_and_preserves_partial_file() {
        use crate::transfer::wire::TransferWireClient;
        tokio::time::timeout(Duration::from_secs(10), async {
            let fixture = fixture(false, false);
            let control = fixture.receiver.clone();
            let (left, right) = tokio::io::duplex(128 * 1024);
            let (client_tls, server_tls) =
                tokio::join!(fixture.client.connect(left), fixture.server.accept(right));
            let (client_conn, server_conn) = tokio::join!(
                vox_transport::establish_client(client_tls.unwrap()),
                fixture.receiver.establish(server_tls.unwrap())
            );
            let client_conn = client_conn.unwrap();
            let _server_conn = server_conn.unwrap();
            let lane: TransferWireClient = client_conn.open_lane().await.unwrap();
            let _error = lane.begin(1, ID.into(), "wrong".into()).await.unwrap_err();
            lane.begin(1, ID.into(), fixture.digest.clone())
                .await
                .unwrap();
            let (tx, rx) = vox::channel::<Vec<u8>>();
            let upload = lane.upload(ID.into(), fixture.digest.clone(), "one".into(), rx);
            let send = async move {
                tx.send(b"he".to_vec()).await.unwrap();
                tx.close(vox::Metadata::default()).await.unwrap();
            };
            let (result, ()) = tokio::join!(upload, send);
            let _error = result.unwrap_err();
            let mut state = control.state.lock().await;
            assert!(state.in_flight_or_failed);
            assert!(state.journal.has_pending_claim("one"));
            assert!(!state.journal.has_observation("one"));
            let file = state.files.get_mut("one").unwrap().file_mut();
            file.seek(SeekFrom::Start(0)).unwrap();
            let mut partial = Vec::new();
            file.read_to_end(&mut partial).unwrap();
            assert_eq!(partial, b"he");
            drop(state);
            assert_eq!(std::fs::read(&fixture.source).unwrap(), b"hello");
        })
        .await
        .expect("partial upload test timed out");
    }

    #[tokio::test]
    async fn identical_duplicate_is_verified_without_overwriting() {
        use crate::transfer::wire::TransferWireClient;
        tokio::time::timeout(Duration::from_secs(10), async {
            let fixture = fixture(false, false);
            let control = fixture.receiver.clone();
            let (left, right) = tokio::io::duplex(128 * 1024);
            let (client_tls, server_tls) =
                tokio::join!(fixture.client.connect(left), fixture.server.accept(right));
            let (client_conn, server_conn) = tokio::join!(
                vox_transport::establish_client(client_tls.unwrap()),
                fixture.receiver.establish(server_tls.unwrap())
            );
            let client_conn = client_conn.unwrap();
            let _server_conn = server_conn.unwrap();
            let lane: TransferWireClient = client_conn.open_lane().await.unwrap();
            lane.begin(1, ID.into(), fixture.digest.clone())
                .await
                .unwrap();
            for _ in 0..2 {
                let (tx, rx) = vox::channel::<Vec<u8>>();
                let upload = lane.upload(ID.into(), fixture.digest.clone(), "one".into(), rx);
                let send = async move {
                    tx.send(b"hello".to_vec()).await.unwrap();
                    tx.close(vox::Metadata::default()).await.unwrap();
                };
                let (result, ()) = tokio::join!(upload, send);
                result.unwrap();
            }
            assert_eq!(
                lane.status(ID.into(), fixture.digest.clone())
                    .await
                    .unwrap(),
                TransferState::BodiesChecked
            );
            let mut state = control.state.lock().await;
            let file = state.files.get_mut("one").unwrap().file_mut();
            file.seek(SeekFrom::Start(0)).unwrap();
            let mut body = Vec::new();
            file.read_to_end(&mut body).unwrap();
            assert_eq!(body, b"hello");
        })
        .await
        .expect("duplicate upload test timed out");
    }

    #[tokio::test]
    async fn oversized_chunk_is_rejected_before_writing() {
        use crate::transfer::wire::TransferWireClient;
        tokio::time::timeout(Duration::from_secs(10), async {
            let fixture = fixture(false, false);
            let control = fixture.receiver.clone();
            let (left, right) = tokio::io::duplex(128 * 1024);
            let (client_tls, server_tls) =
                tokio::join!(fixture.client.connect(left), fixture.server.accept(right));
            let (client_conn, server_conn) = tokio::join!(
                vox_transport::establish_client(client_tls.unwrap()),
                fixture.receiver.establish(server_tls.unwrap())
            );
            let client_conn = client_conn.unwrap();
            let _server_conn = server_conn.unwrap();
            let lane: TransferWireClient = client_conn.open_lane().await.unwrap();
            lane.begin(1, ID.into(), fixture.digest.clone())
                .await
                .unwrap();
            let (tx, rx) = vox::channel::<Vec<u8>>();
            let upload = lane.upload(ID.into(), fixture.digest.clone(), "one".into(), rx);
            let send = async move {
                let _sent = tx
                    .send(vec![
                        0;
                        crate::transfer::verified_stream::MAX_CHUNK_BYTES + 1
                    ])
                    .await;
                let _closed = tx.close(vox::Metadata::default()).await;
            };
            let (result, ()) = tokio::join!(upload, send);
            let _error = result.unwrap_err();
            let mut state = control.state.lock().await;
            assert!(state.in_flight_or_failed);
            assert!(state.journal.has_pending_claim("one"));
            assert_eq!(
                state
                    .files
                    .get_mut("one")
                    .unwrap()
                    .file_mut()
                    .metadata()
                    .unwrap()
                    .len(),
                0
            );
        })
        .await
        .expect("oversized upload test timed out");
    }
}
