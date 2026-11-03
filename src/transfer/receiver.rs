//! Journal-backed, pre-publication receiver.
//!
//! Operational construction is intentionally blocked: a `StagingPermit` cannot
//! yet be created outside this module. Windows staging isolation and publication
//! remain unresolved. No listener, path creation, source deletion or publication
//! is implemented here.

use super::blocking_io::BlockingIoGate;
use super::journal::JournalApproval;
use super::journal::JournalBinding;
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
use std::io::Write;
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

/// Reserved for a future reviewed replay gate that retains qualified final
/// directory, file and transaction handles. No operational constructor exists.
/// Before adding one, review the asynchronous close-signal binding and retain
/// qualified handles for its full lifetime. A fresh authorization mechanism is
/// also needed after expiry. No signal proves instantaneous peer reachability.
/// In a synthetic probe, graceful peer shutdown did not resolve `closed` within
/// two seconds while the service lane stayed open; dropping the lane allowed it
/// to resolve. This signal is not yet a sufficient live replay revocation gate.
#[derive(Debug)]
pub struct ReceiptReplayPermit {
    granted_at: std::time::Instant,
    expires_at: std::time::Instant,
}

impl ReceiptReplayPermit {
    fn remaining(&self) -> Option<Duration> {
        let latest = self.granted_at.checked_add(Duration::from_mins(1))?;
        if self.expires_at > latest || std::time::Instant::now() < self.granted_at {
            return None;
        }
        self.expires_at
            .checked_duration_since(std::time::Instant::now())
            .filter(|value| !value.is_zero())
    }
}

struct State {
    journal: Option<TransactionJournal>,
    manifest: ApprovedManifest,
    digest: String,
    files: BTreeMap<String, ExclusiveFile>,
    begun: bool,
    authenticated_connection: Option<BoundedConnection>,
    replay_permit: Option<ReceiptReplayPermit>,
    in_flight_or_failed: bool,
    deadline: tokio::time::Instant,
    io_gate: BlockingIoGate,
    #[cfg(test)]
    before_file_io: Option<Box<dyn FnOnce() + Send>>,
    #[cfg(test)]
    before_receipt_return: Option<Box<dyn FnOnce() + Send>>,
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
    /// Prepare pre-existing exclusively held files and journal their claims
    /// in a deadline-bounded blocking worker. After timeout or cancellation,
    /// the worker may still hold its handles and its on-disk outcome requires
    /// inspection. This is unavailable until a reviewed staging permit exists.
    ///
    /// # Errors
    /// Rejects mismatched approval, missing files, unsafe claims and I/O errors.
    pub async fn prepare(
        _permit: StagingPermit,
        journal: TransactionJournal,
        approval: &JournalApproval<'_>,
        files: BTreeMap<String, ExclusiveFile>,
    ) -> Result<Self> {
        let _binding = JournalBinding::from_approval(approval)?;
        let manifest = parse_approved_manifest(
            approval.manifest_bytes,
            approval.manifest_sha256,
            approval.transaction_id,
            now()?,
        )?;
        let expiry = UNIX_EPOCH
            .checked_add(Duration::from_secs(manifest.expires_unix()))
            .ok_or_else(|| eyre::eyre!("invalid approval expiry"))?;
        let budget = MAX_IDLE.min(
            expiry
                .duration_since(SystemTime::now())
                .map_err(|_error| eyre::eyre!("approval expired"))?,
        );
        let deadline = std::time::Instant::now()
            .checked_add(budget)
            .ok_or_else(|| eyre::eyre!("preparation deadline overflow"))?;
        let manifest_bytes = approval.manifest_bytes.to_vec();
        let manifest_sha256 = approval.manifest_sha256.to_owned();
        let transaction_id = approval.transaction_id.to_owned();
        let client_pin = approval.client_pin.to_owned();
        let server_pin = approval.server_pin.to_owned();
        let final_name = approval.final_name.to_owned();
        let destination_parent = approval.destination_parent;
        let stage_directory = approval.stage_directory;
        let journal_file = approval.journal_file;
        let gate = BlockingIoGate::default();
        let worker_gate = gate.clone();
        let (journal, manifest, files) = gate
            .run(budget, move || {
                let mut journal = journal;
                let mut files = files;
                let current = now()?;
                check_worker_deadline(&worker_gate, deadline, manifest.expires_unix())?;
                let approval = JournalApproval {
                    manifest_bytes: &manifest_bytes,
                    manifest_sha256: &manifest_sha256,
                    transaction_id: &transaction_id,
                    client_pin: &client_pin,
                    server_pin: &server_pin,
                    destination_parent,
                    stage_directory,
                    journal_file,
                    final_name: &final_name,
                    now_unix: current,
                };
                ensure!(
                    journal.matches_approval(&approval)?,
                    "journal approval mismatch"
                );
                ensure!(files.len() == manifest.files().len(), "file set mismatch");
                for approved in manifest.files() {
                    check_worker_deadline(&worker_gate, deadline, manifest.expires_unix())?;
                    let file = files
                        .get_mut(approved.id())
                        .ok_or_else(|| eyre::eyre!("missing approved file"))?;
                    if journal.has_observation(approved.id()) {
                        file.verify()?;
                        journal.verify_file_before(
                            approved.id(),
                            file.file_mut(),
                            deadline,
                            &worker_gate,
                        )?;
                    } else {
                        journal.claim_empty_file_before(
                            approved.id(),
                            file,
                            deadline,
                            &worker_gate,
                        )?;
                    }
                }
                check_worker_deadline(&worker_gate, deadline, manifest.expires_unix())?;
                Ok((journal, manifest, files))
            })
            .await?;
        Ok(Self {
            state: Arc::new(Mutex::new(State {
                journal: Some(journal),
                manifest,
                digest: approval.manifest_sha256.to_owned(),
                files,
                begun: false,
                authenticated_connection: None,
                replay_permit: None,
                in_flight_or_failed: false,
                deadline: tokio::time::Instant::now() + MAX_SESSION,
                io_gate: gate,
                #[cfg(test)]
                before_file_io: None,
                #[cfg(test)]
                before_receipt_return: None,
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
            let journal = state
                .journal
                .as_ref()
                .ok_or_else(|| eyre::eyre!("journal unavailable"))?;
            (
                journal.matches_client_pin(&stream.client_pin()),
                journal.matches_server_pin(&stream.server_pin()),
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
        let state = Arc::clone(&self.state);
        let connection =
            vox_transport::establish_server(stream, TransferWireDispatcher::new(self)).await?;
        state.lock().await.authenticated_connection = Some(connection.clone());
        Ok(connection)
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
        let journal = state.journal.as_ref().ok_or(TransferError::Failed)?;
        if state
            .manifest
            .files()
            .all(|file| journal.has_observation(file.id()))
        {
            Ok(TransferState::BodiesChecked)
        } else {
            Ok(TransferState::Receiving)
        }
    }

    async fn receipt(
        &self,
        transaction_id: String,
        manifest_sha256: String,
    ) -> std::result::Result<Vec<u8>, TransferError> {
        let mut state = self
            .state
            .try_lock()
            .map_err(|_error| TransferError::NotReady)?;
        check(&state, &transaction_id, &manifest_sha256)?;
        if !state.begun || state.replay_permit.is_none() {
            return Err(TransferError::NotReady);
        }
        let connection = state
            .authenticated_connection
            .clone()
            .ok_or(TransferError::NotReady)?;
        if tokio::select! { biased; () = connection.closed() => true, () = std::future::ready(()) => false }
        {
            return Err(TransferError::NotReady);
        }
        if state.journal.is_none() {
            return Err(TransferError::Failed);
        }
        let replay_remaining = state
            .replay_permit
            .as_ref()
            .and_then(ReceiptReplayPermit::remaining)
            .ok_or(TransferError::Expired)?;
        let (budget, _) = worker_budget(&state).map_err(|_error| TransferError::Expired)?;
        let budget = budget.min(replay_remaining);
        let deadline = std::time::Instant::now()
            .checked_add(budget)
            .ok_or(TransferError::Failed)?;
        let permit = state.replay_permit.take().ok_or(TransferError::NotReady)?;
        let mut journal = state.journal.take().ok_or(TransferError::Failed)?;
        state.in_flight_or_failed = true;
        let gate = state.io_gate.clone();
        let worker_gate = gate.clone();
        #[cfg(test)]
        let before_receipt_return = state.before_receipt_return.take();
        let work = gate.run(budget, move || {
            let bytes = journal.read_recorded_receipt_before(deadline, &worker_gate)?;
            #[cfg(test)]
            if let Some(hook) = before_receipt_return {
                hook();
            }
            worker_gate.ensure_active()?;
            Ok((journal, permit, bytes))
        });
        let result = tokio::select! {
            biased;
            () = connection.closed() => return Err(TransferError::NotReady),
            result = work => result,
        };
        let (journal, permit, bytes) = result.map_err(|_error| TransferError::Failed)?;
        state.journal = Some(journal);
        state.replay_permit = Some(permit);
        state.in_flight_or_failed = false;
        check(&state, &transaction_id, &manifest_sha256)?;
        state
            .replay_permit
            .as_ref()
            .and_then(ReceiptReplayPermit::remaining)
            .ok_or(TransferError::Expired)?;
        if tokio::select! { biased; () = connection.closed() => true, () = std::future::ready(()) => false }
        {
            return Err(TransferError::NotReady);
        }
        Ok(bytes)
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

fn remaining(state: &State) -> Result<Duration> {
    let session = state
        .deadline
        .checked_duration_since(tokio::time::Instant::now())
        .ok_or_else(|| eyre::eyre!("session expired"))?;
    let expiry = UNIX_EPOCH
        .checked_add(Duration::from_secs(state.manifest.expires_unix()))
        .ok_or_else(|| eyre::eyre!("invalid approval expiry"))?;
    let approval = expiry
        .duration_since(SystemTime::now())
        .map_err(|_error| eyre::eyre!("approval expired"))?;
    Ok(session.min(MAX_IDLE).min(approval))
}

fn check_worker_deadline(
    gate: &BlockingIoGate,
    deadline: std::time::Instant,
    expiry: u64,
) -> Result<()> {
    gate.ensure_active()?;
    ensure!(
        std::time::Instant::now() < deadline && now()? < expiry,
        "session expired"
    );
    Ok(())
}

fn worker_budget(state: &State) -> Result<(Duration, std::time::Instant)> {
    let duration = remaining(state)?;
    let deadline = std::time::Instant::now()
        .checked_add(duration)
        .ok_or_else(|| eyre::eyre!("I/O deadline overflow"))?;
    Ok((duration, deadline))
}

async fn receive_body(state: &mut State, id: &str, chunks: &mut vox::Rx<Vec<u8>>) -> Result<()> {
    let completed = state
        .journal
        .as_ref()
        .ok_or_else(|| eyre::eyre!("journal unavailable"))?
        .has_observation(id);
    let approved = state
        .manifest
        .files()
        .find(|file| file.id() == id)
        .ok_or_else(|| eyre::eyre!("unknown file"))?;
    let mut file = state
        .files
        .remove(id)
        .ok_or_else(|| eyre::eyre!("missing file"))?;
    let gate = state.io_gate.clone();
    let expires = state.manifest.expires_unix();
    let (budget, deadline) = worker_budget(state)?;
    let worker_gate = gate.clone();
    #[cfg(test)]
    let before_file_io = state.before_file_io.take();
    file = gate
        .run(budget, move || {
            #[cfg(test)]
            if let Some(hook) = before_file_io {
                hook();
            }
            check_worker_deadline(&worker_gate, deadline, expires)?;
            file.verify()?;
            check_worker_deadline(&worker_gate, deadline, expires)?;
            if !completed {
                ensure!(
                    file.file_mut().metadata()?.len() == 0,
                    "partial file requires inspection"
                );
                check_worker_deadline(&worker_gate, deadline, expires)?;
                file.file_mut().seek(SeekFrom::Start(0))?;
            }
            check_worker_deadline(&worker_gate, deadline, expires)?;
            Ok(file)
        })
        .await?;
    state.files.insert(id.to_owned(), file);
    // Check each incoming chunk before passing its bounded bytes to the worker.
    // Completed duplicates are checked against a sink and never overwritten.
    let mut verifier = FileVerifier::new(approved, std::io::sink());
    loop {
        let item = tokio::time::timeout(remaining(state)?, chunks.recv()).await??;
        match item {
            Some(chunk) => {
                verifier.push(chunk.get())?;
                if !completed {
                    let bytes = chunk.get().clone();
                    let (budget, deadline) = worker_budget(state)?;
                    let worker_gate = gate.clone();
                    let mut file = state
                        .files
                        .remove(id)
                        .ok_or_else(|| eyre::eyre!("missing file"))?;
                    let file = gate
                        .run(budget, move || {
                            check_worker_deadline(&worker_gate, deadline, expires)?;
                            file.file_mut().write_all(&bytes)?;
                            check_worker_deadline(&worker_gate, deadline, expires)?;
                            Ok(file)
                        })
                        .await?;
                    state.files.insert(id.to_owned(), file);
                }
            }
            None => break,
        }
    }
    verifier.finish()?;
    let mut file = state
        .files
        .remove(id)
        .ok_or_else(|| eyre::eyre!("missing file"))?;
    let mut journal = state
        .journal
        .take()
        .ok_or_else(|| eyre::eyre!("journal unavailable"))?;
    let approved_id = id.to_owned();
    let (budget, deadline) = worker_budget(state)?;
    let worker_gate = gate.clone();
    let (journal, file) = gate
        .run(budget, move || {
            check_worker_deadline(&worker_gate, deadline, expires)?;
            journal.verify_file_before(&approved_id, file.file_mut(), deadline, &worker_gate)?;
            check_worker_deadline(&worker_gate, deadline, expires)?;
            file.verify()?;
            check_worker_deadline(&worker_gate, deadline, expires)?;
            Ok((journal, file))
        })
        .await?;
    state.journal = Some(journal);
    state.files.insert(id.to_owned(), file);
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

    fn synthetic_replay_permit() -> ReceiptReplayPermit {
        let granted_at = std::time::Instant::now();
        ReceiptReplayPermit {
            granted_at,
            expires_at: granted_at + Duration::from_mins(1),
        }
    }

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
        dir: tempfile::TempDir,
        source: std::path::PathBuf,
        raw: String,
        digest: String,
        receiver: Receiver,
        client: ClientEndpoint,
        server: ServerEndpoint,
    }

    async fn fixture(wrong_journal_pin: bool, wrong_server_pin: bool) -> Fixture {
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
        let receiver = Receiver::prepare(StagingPermit(()), journal, &approval, files)
            .await
            .unwrap();
        Fixture {
            dir,
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
            let fixture = fixture(false, false).await;
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
            assert!(state.journal.as_ref().unwrap().has_observation("one"));
            let mut bytes = Vec::new();
            let file = state.files.get_mut("one").unwrap().file_mut();
            file.seek(SeekFrom::Start(0)).unwrap();
            file.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, b"hello");
            drop(state);
            assert!(matches!(
                control.receipt(ID.into(), fixture.digest.clone()).await,
                Err(TransferError::NotReady)
            ));
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
    async fn protected_three_file_staging_reaches_journal_intent_without_publication() {
        protected_three_file_simulation(false, false, None, false).await;
    }

    #[tokio::test]
    async fn protected_precommit_rejects_unexpected_stage_entry() {
        protected_three_file_simulation(false, false, None, true).await;
    }

    #[tokio::test]
    #[ignore = "manual NTFS coordinated publication probe; synthetic permit only"]
    async fn coordinated_commit_publishes_three_verified_files() {
        protected_three_file_simulation_inner(true, false, None, false, CommitMode::Coordinated).await;
    }

    #[tokio::test]
    #[ignore = "manual NTFS coordinated collision probe; synthetic permit only"]
    async fn coordinated_commit_preserves_existing_destination() {
        protected_three_file_simulation_inner(true, true, None, false, CommitMode::Coordinated).await;
    }

    #[tokio::test]
    #[ignore = "manual NTFS timeout probe; synthetic permit only"]
    async fn coordinated_commit_timeout_after_intent_preserves_stage() {
        protected_three_file_simulation_inner(true, false, None, false, CommitMode::Timeout).await;
    }

    #[tokio::test]
    #[ignore = "manual NTFS cancellation probe; synthetic permit only"]
    async fn coordinated_commit_cancellation_after_intent_preserves_stage() {
        protected_three_file_simulation_inner(true, false, None, false, CommitMode::Cancel).await;
    }

    #[tokio::test]
    async fn coordinated_commit_rejects_wrong_target_before_intent() {
        protected_three_file_simulation_inner(true, false, None, false, CommitMode::WrongTarget).await;
    }

    #[tokio::test]
    #[ignore = "manual NTFS rename and journal-reopen probe; not a durability or staging qualification"]
    async fn protected_three_file_rename_and_reopen_recovery() {
        protected_three_file_simulation(true, false, None, false).await;
    }

    #[tokio::test]
    #[ignore = "manual NTFS no-replace collision probe; not a staging qualification"]
    async fn protected_three_file_rename_preserves_existing_destination() {
        protected_three_file_simulation(true, true, None, false).await;
    }

    #[tokio::test]
    #[ignore = "manual NTFS timeout after synthetic rename; not crash or durability proof"]
    async fn protected_rename_timeout_keeps_resources_until_worker_finishes() {
        protected_three_file_simulation(true, false, Some((false, false)), false).await;
    }

    #[tokio::test]
    #[ignore = "manual NTFS cancellation after synthetic rename; not crash or durability proof"]
    async fn protected_rename_cancellation_keeps_resources_until_worker_finishes() {
        protected_three_file_simulation(true, false, Some((true, false)), false).await;
    }

    #[tokio::test]
    #[ignore = "manual NTFS timeout after published record; not crash or durability proof"]
    async fn timeout_after_published_record_does_not_issue_receipt() {
        protected_three_file_simulation(true, false, Some((false, true)), false).await;
    }

    #[tokio::test]
    async fn synthetic_crash_child() {
        if std::env::var_os("TEAMY_TEST_CRASH_ROOT").is_some() {
            protected_three_file_simulation(true, false, None, false).await;
            panic!("synthetic crash hook did not terminate the child");
        }
    }

    #[test]
    #[ignore = "manual NTFS abrupt-process recovery probe; not power-loss durability proof"]
    fn abrupt_process_after_published_record_allows_local_inspection_only() {
        abrupt_process_recovery("after-published", 77, true);
    }

    #[test]
    #[ignore = "manual NTFS abrupt-process recovery probe; not power-loss durability proof"]
    fn abrupt_process_after_rename_remains_ambiguous() {
        abrupt_process_recovery("after-rename", 78, false);
    }

    #[expect(
        clippy::too_many_lines,
        reason = "keep the child-process crash and local inspection sequence together"
    )]
    fn abrupt_process_recovery(crash_point: &str, expected_exit: i32, published_recorded: bool) {
        use crate::transfer::recovery::RecoveryDisposition;
        use crate::transfer::transaction_journal::LocalInspection;
        use crate::transfer::windows_acl::open_checked_child;
        use crate::transfer::windows_lock::directory_identity;
        use std::os::windows::fs::OpenOptionsExt;
        use std::process::{Command, Stdio};
        use windows::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        };

        let root = tempfile::tempdir().unwrap();
        let verified_root = std::fs::canonicalize(root.path()).unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "transfer::receiver::tests::synthetic_crash_child",
                "--nocapture",
            ])
            .env("TEAMY_TEST_CRASH_ROOT", &verified_root)
            .env("TEAMY_TEST_CRASH_POINT", crash_point)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                let _killed = child.kill();
                let _waited = child.wait();
                panic!("synthetic crash child did not terminate");
            }
            std::thread::sleep(Duration::from_millis(25));
        };
        assert_eq!(status.code(), Some(expected_exit));
        let children: Vec<_> = std::fs::read_dir(&verified_root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(children.len(), 1);
        let fixture = std::fs::canonicalize(&children[0]).unwrap();
        assert!(fixture.starts_with(&verified_root) && fixture != verified_root);
        let config = std::fs::read_to_string(fixture.join("fixture-approval.txt")).unwrap();
        let values: Vec<_> = config.lines().collect();
        assert_eq!(values.len(), 4);
        let private_path = fixture.join("private");
        let parent = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(&private_path)
            .unwrap();
        let parent_id = directory_identity(&parent).unwrap();
        let published = open_checked_child(&parent, parent_id, "published", false).unwrap();
        let stage_id = directory_identity(&published).unwrap();
        let journal_path = private_path.join("journal.bin");
        let journal_id = regular_file_identity(&File::open(&journal_path).unwrap()).unwrap();
        let object = |id: crate::transfer::windows_lock::FileIdentity| ObjectIdentity {
            volume_serial: id.volume_serial,
            file_index: id.file_index,
        };
        let approval = JournalApproval {
            manifest_bytes: values[0].as_bytes(),
            manifest_sha256: values[1],
            transaction_id: ID,
            client_pin: values[2],
            server_pin: values[3],
            destination_parent: object(parent_id),
            stage_directory: object(stage_id),
            journal_file: object(journal_id),
            final_name: "published",
            now_unix: now().unwrap(),
        };
        let original_journal = std::fs::read(&journal_path).unwrap();
        let lock = ExclusiveFile::acquire(&journal_path, journal_id).unwrap();
        let journal = TransactionJournal::reopen(lock, &approval).unwrap();
        assert_eq!(journal.has_published_record(), published_recorded);
        assert!(journal.recorded_receipt().is_none());
        drop(journal);
        let lock = ExclusiveFile::acquire(&journal_path, journal_id).unwrap();
        let mut inspection = LocalInspection::open(lock, &approval).unwrap();
        assert_eq!(
            inspection.disposition(),
            if published_recorded {
                RecoveryDisposition::InspectPublished
            } else {
                RecoveryDisposition::InspectAmbiguousPublication
            }
        );
        let ids = ["one", "two", "three"];
        let names = ["one.bin", "two.bin", "three.bin"];
        let bodies: [&[u8]; 3] = [b"one", b"two", b"three"];
        let mut files = BTreeMap::new();
        for (id, name) in ids.iter().zip(names) {
            let path = private_path.join("published").join(name);
            let file_id = regular_file_identity(&File::open(&path).unwrap()).unwrap();
            files.insert(
                (*id).to_owned(),
                ExclusiveFile::acquire(&path, file_id).unwrap(),
            );
        }
        inspection
            .inspect_final_contents(&parent, &mut files)
            .unwrap();
        drop(files);
        drop(inspection);
        assert_eq!(std::fs::read(&journal_path).unwrap(), original_journal);
        for (id, body) in ids.iter().zip(bodies) {
            assert_eq!(
                std::fs::read(fixture.join(format!("source-{id}"))).unwrap(),
                body
            );
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum CommitMode {
        Manual,
        Coordinated,
        Timeout,
        Cancel,
        WrongTarget,
    }

    async fn protected_three_file_simulation(
        attempt_rename: bool,
        collision: bool,
        interrupted: Option<(bool, bool)>,
        unexpected_entry: bool,
    ) {
        protected_three_file_simulation_inner(
            attempt_rename,
            collision,
            interrupted,
            unexpected_entry,
            CommitMode::Manual,
        )
        .await;
    }

    #[expect(
        clippy::too_many_lines,
        reason = "keep the synthetic transfer, rename and reconciliation sequence together"
    )]
    async fn protected_three_file_simulation_inner(
        attempt_rename: bool,
        collision: bool,
        interrupted: Option<(bool, bool)>,
        unexpected_entry: bool,
        mode: CommitMode,
    ) {
        use crate::transfer::recovery::RecoveryDisposition;
        use crate::transfer::transaction_journal::LocalInspection;
        use crate::transfer::windows_acl::{
            create_private_child, create_private_file, create_synthetic_private_directory,
            open_checked_child,
        };
        use crate::transfer::windows_lock::directory_identity;
        use crate::transfer::windows_publish::{
            RenameOutcome, commit_qualified_stage, rename_with_permit_and_ancestry,
            synthetic_commit_with_hook, synthetic_delayed_rename, synthetic_permit,
            synthetic_qualified_commit,
        };
        use crate::transfer::windows_stage::{ExpectedEntry, verify_entries};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        tokio::time::timeout(Duration::from_secs(15), Box::pin(async {
            let crash_root = std::env::var_os("TEAMY_TEST_CRASH_ROOT");
            let crash_point = crash_root.as_ref().map(|_| std::env::var("TEAMY_TEST_CRASH_POINT").unwrap());
            assert!(crash_point.as_deref().is_none_or(|point| point == "after-rename" || point == "after-published"));
            let dir = if let Some(root) = &crash_root {
                tempfile::Builder::new().prefix("crash-child-").tempdir_in(root).unwrap()
            } else {
                tempfile::tempdir().unwrap()
            };
            let parent = create_synthetic_private_directory(&dir.path().join("private")).unwrap();
            let parent_id = directory_identity(&parent).unwrap();
            let stage = create_private_child(&parent, parent_id, "stage").unwrap();
            let stage_id = directory_identity(&stage).unwrap();
            let journal_file = create_private_file(&parent, parent_id, "journal.bin").unwrap();
            let journal_id = journal_file.identity();
            let bodies: [&[u8]; 3] = [b"one", b"two", b"three"];
            let ids = ["one", "two", "three"];
            let names = ["one.bin", "two.bin", "three.bin"];
            let mut sources = Vec::new();
            let mut files = BTreeMap::new();
            let mut entries = Vec::new();
            let mut manifest_files = Vec::new();
            for ((id, name), body) in ids.iter().zip(names).zip(bodies) {
                let source_path = dir.path().join(format!("source-{id}"));
                std::fs::write(&source_path, body).unwrap();
                sources.push(Source::from_file((*id).to_owned(), File::open(&source_path).unwrap()));
                let staged = create_private_file(&stage, stage_id, name).unwrap();
                entries.push(ExpectedEntry { name, identity: staged.identity(), size: u64::try_from(body.len()).unwrap() });
                files.insert((*id).to_owned(), staged);
                let hash = format!("{:x}", Sha256::digest(body));
                manifest_files.push(format!(r#"{{"id":"{id}","name":"{name}","sha256":"{hash}","size":{}}}"#, body.len()));
            }
            let expiry = now().unwrap() + 600;
            let raw = format!(r#"{{"aggregate_bytes":11,"expires_unix":{expiry},"file_count":3,"files":[{}],"transaction_id":"{ID}","version":1}}"#, manifest_files.join(","));
            let digest = format!("{:x}", Sha256::digest(raw.as_bytes()));
            let (client, server, client_pin, server_pin) = certificates();
            if crash_root.is_some() {
                std::fs::write(dir.path().join("fixture-approval.txt"), format!("{raw}\n{digest}\n{client_pin}\n{server_pin}\n")).unwrap();
            }
            let object = |id: crate::transfer::windows_lock::FileIdentity| ObjectIdentity {
                volume_serial: id.volume_serial, file_index: id.file_index,
            };
            let approval = JournalApproval {
                manifest_bytes: raw.as_bytes(), manifest_sha256: &digest, transaction_id: ID,
                client_pin: &client_pin, server_pin: &server_pin,
                destination_parent: object(parent_id), stage_directory: object(stage_id),
                journal_file: object(journal_id), final_name: "published", now_unix: now().unwrap(),
            };
            let journal = TransactionJournal::initialize(journal_file, &approval).unwrap();
            let receiver = Receiver::prepare(StagingPermit(()), journal, &approval, files).await.unwrap();
            let control = receiver.clone();
            // A synthetic CONNECT tunnel exercises the actual bounded sender,
            // mutual TLS, Vox driver and journal-backed receiver together.
            // The fake stage permit and in-memory tunnel do not qualify a live
            // destination or prove the cloud route is reachable.
            let (left, mut right) = tokio::io::duplex(128 * 1024);
            let (finished_tx, finished_rx) = tokio::sync::oneshot::channel::<()>();
            let receiver_tls = server.clone();
            let proxy_and_receiver = async move {
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    assert!(request.len() < 8192);
                    request.push(right.read_u8().await.unwrap());
                }
                assert!(request.starts_with(b"CONNECT 100.64.0.1:49152 HTTP/1.1\r\n"));
                right.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await.unwrap();
                let authenticated = receiver_tls.accept(right).await.unwrap();
                let connection = receiver.establish(authenticated).await.unwrap();
                let _finished = finished_rx.await;
                connection
            };
            let sender = async {
                let result = crate::transfer::sender::send_prepublication_via_proxy(
                    left, "100.64.0.1:49152", &client, raw.as_bytes(), &digest, ID, sources,
                ).await;
                let _sent = finished_tx.send(());
                result
            };
            let (sent, _server_conn) = tokio::join!(sender, proxy_and_receiver);
            sent.unwrap();
            let mut receiver_state = control.state.lock().await;
            for (id, expected) in ids.iter().zip(bodies) {
                assert!(receiver_state.journal.as_ref().unwrap().has_observation(id));
                let file = receiver_state.files.get_mut(*id).unwrap().file_mut();
                file.seek(SeekFrom::Start(0)).unwrap();
                let mut actual = Vec::new();
                file.read_to_end(&mut actual).unwrap();
                assert_eq!(actual, expected);
            }
            verify_entries(&stage, stage_id, &entries).unwrap();
            if mode != CommitMode::Manual {
                assert!(attempt_rename && interrupted.is_none() && !unexpected_entry);
                if collision {
                    let existing = create_private_child(&parent, parent_id, "published").unwrap();
                    let existing_id = directory_identity(&existing).unwrap();
                    let mut marker = create_private_file(&existing, existing_id, "existing.bin").unwrap();
                    marker.file_mut().write_all(b"already here").unwrap();
                    drop(marker);
                    drop(existing);
                }
                let journal = receiver_state.journal.take().unwrap();
                let files = std::mem::take(&mut receiver_state.files);
                drop(receiver_state);
                let gate = BlockingIoGate::default();
                let final_name = if mode == CommitMode::WrongTarget { "wrong" } else { "published" };
                let input = synthetic_qualified_commit(journal, files, stage, parent, gate.clone(), final_name);
                if mode == CommitMode::WrongTarget {
                    let _error = commit_qualified_stage(input, Duration::from_secs(3)).await.unwrap_err();
                    let journal_path = dir.path().join("private/journal.bin");
                    let lock = ExclusiveFile::acquire(&journal_path, journal_id).unwrap();
                    let reopened = TransactionJournal::reopen(lock, &approval).unwrap();
                    assert!(reopened.commit_intent_stage().is_none());
                    assert!(!dir.path().join("private/wrong").exists());
                    assert!(!dir.path().join("private/published").exists());
                    assert!(dir.path().join("private/stage").is_dir());
                    return;
                }
                if matches!(mode, CommitMode::Timeout | CommitMode::Cancel) {
                    assert!(!collision);
                    let (release, wait) = std::sync::mpsc::channel::<()>();
                    let (started, started_rx) = tokio::sync::oneshot::channel::<()>();
                    let hook = move || { let _sent = started.send(()); let _released = wait.recv(); };
                    let task = tokio::spawn(synthetic_commit_with_hook(input, Duration::from_millis(500), hook));
                    tokio::time::timeout(Duration::from_secs(3), started_rx).await.unwrap().unwrap();
                    if mode == CommitMode::Cancel {
                        task.abort();
                        assert!(task.await.unwrap_err().is_cancelled());
                    } else {
                        let _timeout = task.await.unwrap().unwrap_err();
                    }
                    let journal_path = dir.path().join("private/journal.bin");
                    let _held = ExclusiveFile::acquire(&journal_path, journal_id).unwrap_err();
                    let _file_held = std::fs::OpenOptions::new().write(true).open(dir.path().join("private/stage/one.bin")).unwrap_err();
                    assert!(!dir.path().join("private/published").exists());
                    assert!(gate.run(Duration::from_secs(1), || Ok(())).await.is_err());
                    release.send(()).unwrap();
                    let lock = tokio::time::timeout(Duration::from_secs(3), async {
                        loop {
                            if let Ok(lock) = ExclusiveFile::acquire(&journal_path, journal_id) { break lock; }
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    }).await.expect("precommit worker did not release resources");
                    let recovered = TransactionJournal::reopen(lock, &approval).unwrap();
                    assert!(recovered.commit_intent_stage().is_some());
                    assert!(recovered.recorded_receipt().is_none());
                    assert!(!dir.path().join("private/published").exists());
                    for (id, body) in ids.iter().zip(bodies) {
                        assert_eq!(std::fs::read(dir.path().join(format!("source-{id}"))).unwrap(), body);
                    }
                    return;
                }
                let result = commit_qualified_stage(input, Duration::from_secs(3)).await.unwrap();
                if collision {
                    assert!(matches!(result.outcome, RenameOutcome::Unconfirmed { .. }));
                    assert!(result.journal.recorded_receipt().is_none());
                    assert_eq!(std::fs::read(dir.path().join("private/published/existing.bin")).unwrap(), b"already here");
                } else {
                    assert_eq!(result.outcome, RenameOutcome::RenamedDurabilityUnconfirmed);
                    assert!(result.journal.recorded_receipt().unwrap().contains("published-durability-unconfirmed"));
                    assert_eq!(result.ancestry.len(), 1);
                    for (name, body) in names.iter().zip(bodies) {
                        assert_eq!(std::fs::read(dir.path().join("private/published").join(name)).unwrap(), body);
                    }
                }
                for (id, body) in ids.iter().zip(bodies) {
                    assert_eq!(std::fs::read(dir.path().join(format!("source-{id}"))).unwrap(), body);
                }
                return;
            }
            if unexpected_entry {
                drop(create_private_file(&stage, stage_id, "unexpected.bin").unwrap());
            }
            // Move all open stage resources into the deadline-bound worker.
            // This is still a synthetic setup, not a staging/publication permit.
            let (budget, deadline) = worker_budget(&receiver_state).unwrap();
            let gate = receiver_state.io_gate.clone();
            let worker_gate = gate.clone();
            let mut journal = receiver_state.journal.take().unwrap();
            let mut files = std::mem::take(&mut receiver_state.files);
            let prepared = gate.run(budget, move || {
                journal.prepare_staged_commit_before(&stage, &mut files, deadline, &worker_gate)?;
                Ok((journal, files, stage))
            }).await;
            if unexpected_entry {
                assert!(prepared.is_err());
                drop(receiver_state);
                let lock = ExclusiveFile::acquire(&dir.path().join("private/journal.bin"), journal_id).unwrap();
                let reopened = TransactionJournal::reopen(lock, &approval).unwrap();
                assert!(reopened.commit_intent_stage().is_none());
                assert!(dir.path().join("private/stage/unexpected.bin").exists());
                assert!(!dir.path().join("private/published").exists());
                for (id, body) in ids.iter().zip(bodies) {
                    assert_eq!(std::fs::read(dir.path().join(format!("source-{id}"))).unwrap(), body);
                }
                return;
            }
            let (journal, files, stage) = prepared.unwrap();
            receiver_state.journal = Some(journal);
            receiver_state.files = files;
            let journal = receiver_state.journal.as_mut().unwrap();
            assert!(journal.intent_matches_directory(&stage).unwrap());
            assert!(journal.commit().is_err());
            if attempt_rename {
                receiver_state.files.clear();
                let mut journal = receiver_state.journal.take().unwrap();
                drop(receiver_state);
                let _wrong_target = journal.check_publication_binding(&parent, &stage, "wrong").unwrap_err();
                if crash_point.as_deref() == Some("after-published") {
                    journal.set_before_receipt(Box::new(|| std::process::exit(77)));
                }
                if let Some((cancel, after_published)) = interrupted {
                    use std::os::windows::fs::OpenOptionsExt;
                    use windows::Win32::Storage::FileSystem::{FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT};
                    let gate = BlockingIoGate::default();
                    // This locked temporary file stands in for a held ancestor;
                    // it tests worker ownership, not ancestry qualification.
                    let ancestry_path = dir.path().join("synthetic-ancestry-handle");
                    let ancestry = std::fs::OpenOptions::new().read(true).write(true)
                        .create_new(true).share_mode(0).open(&ancestry_path).unwrap();
                    let (release, wait) = std::sync::mpsc::channel::<()>();
                    let (started, started_rx) = tokio::sync::oneshot::channel::<()>();
                    let pause = move || { let _sent = started.send(()); let _released = wait.recv(); };
                    let task = if after_published {
                        journal.set_before_receipt(Box::new(pause));
                        tokio::spawn(synthetic_delayed_rename(gate.clone(), journal, stage, (parent, vec![ancestry]), Duration::from_millis(500), || {}))
                    } else {
                        tokio::spawn(synthetic_delayed_rename(gate.clone(), journal, stage, (parent, vec![ancestry]), Duration::from_millis(500), pause))
                    };
                    tokio::time::timeout(Duration::from_secs(3), started_rx).await.unwrap().unwrap();
                    if cancel {
                        task.abort();
                        assert!(task.await.unwrap_err().is_cancelled());
                    } else {
                        let _timeout = task.await.unwrap().unwrap_err();
                    }
                    let journal_path = dir.path().join("private/journal.bin");
                    let _held = ExclusiveFile::acquire(&journal_path, journal_id).unwrap_err();
                    let _held_ancestor = std::fs::OpenOptions::new().write(true).open(&ancestry_path).unwrap_err();
                    assert!(dir.path().join("private/published").is_dir());
                    assert!(gate.run(Duration::from_secs(1), || Ok(())).await.is_err());
                    release.send(()).unwrap();
                    let lock = tokio::time::timeout(Duration::from_secs(3), async {
                        loop {
                            if let Ok(lock) = ExclusiveFile::acquire(&journal_path, journal_id) { break lock; }
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    }).await.expect("rename worker did not release resources");
                    let _released_ancestor = std::fs::OpenOptions::new().write(true).open(&ancestry_path).unwrap();
                    assert!(gate.run(Duration::from_secs(1), || Ok(())).await.is_err());
                    let mut recovered = TransactionJournal::reopen(lock, &approval).unwrap();
                    assert!(recovered.recorded_receipt().is_none());
                    assert_eq!(recovered.has_published_record(), after_published);
                    let parent_again = std::fs::OpenOptions::new().read(true)
                        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
                        .open(dir.path().join("private")).unwrap();
                    let published = open_checked_child(&parent_again, parent_id, "published", false).unwrap();
                    assert!(recovered.intent_matches_directory(&published).unwrap());
                    verify_entries(&published, stage_id, &entries).unwrap();
                    for (id, entry) in ids.iter().zip(&entries) {
                        let path = dir.path().join("private/published").join(entry.name);
                        let mut file = ExclusiveFile::acquire(&path, entry.identity).unwrap();
                        recovered.reverify_intent_file(id, file.file_mut(), now().unwrap()).unwrap();
                    }
                    assert!(recovered.commit().is_err());
                    for (id, body) in ids.iter().zip(bodies) {
                        assert_eq!(std::fs::read(dir.path().join(format!("source-{id}"))).unwrap(), body);
                    }
                    return;
                }
                if collision {
                    let existing = create_private_child(&parent, parent_id, "published").unwrap();
                    let existing_id = directory_identity(&existing).unwrap();
                    let mut marker = create_private_file(&existing, existing_id, "existing.bin").unwrap();
                    marker.file_mut().write_all(b"already here").unwrap();
                    drop(marker);
                    let ancestor = parent.try_clone().unwrap();
                    let result = rename_with_permit_and_ancestry(synthetic_permit(), journal, stage, parent, vec![ancestor], "published".to_owned(), Duration::from_secs(3)).await.unwrap();
                    assert_eq!(result.ancestry.len(), 1);
                    assert!(matches!(result.outcome, RenameOutcome::Unconfirmed { .. }));
                    assert!(result.journal.recorded_receipt().is_none());
                    assert!(result.journal.intent_matches_directory(&result.stage).unwrap());
                    assert!(!result.journal.intent_matches_directory(&existing).unwrap());
                    verify_entries(&result.stage, stage_id, &entries).unwrap();
                    assert_eq!(std::fs::read(dir.path().join("private/published/existing.bin")).unwrap(), b"already here");
                    assert!(result.journal.commit().is_err());
                    for (id, body) in ids.iter().zip(bodies) {
                        assert_eq!(std::fs::read(dir.path().join(format!("source-{id}"))).unwrap(), body);
                    }
                    return;
                }
                let result = if crash_point.as_deref() == Some("after-rename") {
                    synthetic_delayed_rename(BlockingIoGate::default(), journal, stage, (parent, Vec::new()), Duration::from_secs(3), || std::process::exit(78)).await.unwrap()
                } else {
                    let ancestor = parent.try_clone().unwrap();
                    rename_with_permit_and_ancestry(synthetic_permit(), journal, stage, parent, vec![ancestor], "published".to_owned(), Duration::from_secs(3)).await.unwrap()
                };
                assert_eq!(result.outcome, RenameOutcome::RenamedDurabilityUnconfirmed);
                let receipt = result.journal.recorded_receipt().unwrap().to_owned();
                assert!(receipt.contains("published-durability-unconfirmed"));
                let parent = result.destination_parent;
                let _held_stage = result.stage;
                // This test fabricates a replay permit solely to exercise the
                // authenticated protocol. No production permit constructor exists.
                let replay = Receiver {
                    state: Arc::new(Mutex::new(State {
                        journal: Some(result.journal),
                        manifest: parse_approved_manifest(raw.as_bytes(), &digest, ID, now().unwrap()).unwrap(),
                        digest: digest.clone(), files: BTreeMap::new(), begun: false,
                        authenticated_connection: None, replay_permit: Some(synthetic_replay_permit()),
                        in_flight_or_failed: false, deadline: tokio::time::Instant::now() + Duration::from_secs(10),
                        io_gate: BlockingIoGate::default(), before_file_io: None, before_receipt_return: None,
                    })),
                    started: Arc::new(AtomicBool::new(false)),
                };
                let replay_control = replay.clone();
                replay_control.begin(1, ID.into(), digest.clone()).await.unwrap();
                assert!(matches!(replay_control.receipt(ID.into(), digest.clone()).await, Err(TransferError::NotReady)));
                let (replay_left, mut bridge_left) = tokio::io::duplex(128 * 1024);
                let (replay_right, mut bridge_right) = tokio::io::duplex(128 * 1024);
                let replay_bridge = tokio::spawn(async move {
                    let _result = tokio::io::copy_bidirectional(&mut bridge_left, &mut bridge_right).await;
                });
                let (client_tls, server_tls) = tokio::join!(client.connect(replay_left), server.accept(replay_right));
                let (client_conn, server_conn) = tokio::join!(
                    vox_transport::establish_client(client_tls.unwrap()), replay.establish(server_tls.unwrap())
                );
                let replay_client = client_conn.unwrap();
                let replay_server = server_conn.unwrap();
                let lane: crate::transfer::wire::TransferWireClient = replay_client.open_lane().await.unwrap();
                lane.begin(1, ID.into(), digest.clone()).await.unwrap();
                assert!(matches!(lane.receipt(ID.into(), "0".repeat(64)).await, Err(vox::VoxError::User(error)) if *error == TransferError::Rejected));
                assert_eq!(lane.receipt(ID.into(), digest.clone()).await.unwrap(), receipt.as_bytes());
                assert_eq!(lane.receipt(ID.into(), digest.clone()).await.unwrap(), receipt.as_bytes());
                let mut replay_state = replay_control.state.lock().await;
                let permit = replay_state.replay_permit.as_mut().unwrap();
                permit.expires_at = permit.granted_at + Duration::from_secs(61);
                drop(replay_state);
                assert!(matches!(lane.receipt(ID.into(), digest.clone()).await, Err(vox::VoxError::User(error)) if *error == TransferError::Expired));
                let mut replay_state = replay_control.state.lock().await;
                replay_state.replay_permit = Some(synthetic_replay_permit());
                replay_state.deadline = tokio::time::Instant::now();
                drop(replay_state);
                assert!(matches!(lane.receipt(ID.into(), digest.clone()).await, Err(vox::VoxError::User(error)) if *error == TransferError::Expired));
                let mut replay_state = replay_control.state.lock().await;
                replay_state.deadline = tokio::time::Instant::now() + Duration::from_secs(5);
                drop(replay_state);
                let journal_path = dir.path().join("private/journal.bin");
                // The same receiver cannot be rebound to a second authenticated
                // connection, even while the first one remains open.
                let (left, right) = tokio::io::duplex(128 * 1024);
                let (_new_client_tls, new_server_tls) = tokio::join!(client.connect(left), server.accept(right));
                let error = replay_control.clone().establish(new_server_tls.unwrap()).await.unwrap_err();
                assert!(error.to_string().contains("already started"));
                // Disconnect after the receipt was read but before the worker
                // can return it. The worker retains its journal until released.
                let (release, wait) = std::sync::mpsc::channel::<()>();
                let (started, started_rx) = tokio::sync::oneshot::channel::<()>();
                replay_control.state.lock().await.before_receipt_return = Some(Box::new(move || {
                    let _sent = started.send(()); let _released = wait.recv();
                }));
                let request = replay_control.clone();
                let request_digest = digest.clone();
                let pending = tokio::spawn(async move { request.receipt(ID.into(), request_digest).await });
                started_rx.await.unwrap();
                replay_bridge.abort();
                let _bridge_stopped = replay_bridge.await.unwrap_err();
                tokio::time::timeout(Duration::from_secs(2), replay_server.closed()).await.unwrap();
                let result = tokio::time::timeout(Duration::from_secs(2), pending).await.unwrap().unwrap();
                assert!(matches!(result, Err(TransferError::NotReady)));
                drop(lane);
                let _still_locked = ExclusiveFile::acquire(&journal_path, journal_id).unwrap_err();
                release.send(()).unwrap();
                let reopened = tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        if let Ok(lock) = ExclusiveFile::acquire(&journal_path, journal_id) { break lock; }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }).await.expect("replay worker did not release its journal");
                let mut recovered = TransactionJournal::reopen(reopened, &approval).unwrap();
                assert_eq!(recovered.recorded_receipt(), Some(receipt.as_str()));
                let published = open_checked_child(&parent, parent_id, "published", false).unwrap();
                assert!(recovered.intent_matches_directory(&published).unwrap());
                assert!(!recovered.intent_matches_directory(&parent).unwrap());
                verify_entries(&published, stage_id, &entries).unwrap();
                for (id, entry) in ids.iter().zip(&entries) {
                    let path = dir.path().join("private/published").join(entry.name);
                    let mut file = ExclusiveFile::acquire(&path, entry.identity).unwrap();
                    recovered.reverify_intent_file(id, file.file_mut(), now().unwrap()).unwrap();
                }
                assert!(recovered.commit().is_err());
                drop(recovered);
                let expired = JournalApproval { now_unix: expiry, ..approval };
                let lock = ExclusiveFile::acquire(&journal_path, journal_id).unwrap();
                let _expired_live_reopen = TransactionJournal::reopen(lock, &expired).unwrap_err();
                let original_journal = std::fs::read(&journal_path).unwrap();
                let lock = ExclusiveFile::acquire(&journal_path, journal_id).unwrap();
                let inspection = LocalInspection::open(lock, &expired).unwrap();
                assert_eq!(inspection.disposition(), RecoveryDisposition::InspectPublished);
                assert!(inspection.intent_matches_directory(&published).unwrap());
                let mut inspected_files = BTreeMap::new();
                for (id, entry) in ids.iter().zip(&entries) {
                    let path = dir.path().join("private/published").join(entry.name);
                    inspected_files.insert((*id).to_owned(), ExclusiveFile::acquire(&path, entry.identity).unwrap());
                }
                // Stall before inspection to model a worker whose OS call has
                // not returned. This is not a real pending-kernel-I/O test.
                let parent_after_stall = parent.try_clone().unwrap();
                let (release, wait) = std::sync::mpsc::channel::<()>();
                let (started, started_rx) = tokio::sync::oneshot::channel::<()>();
                let inspection_gate = BlockingIoGate::default();
                let stalled_gate = inspection_gate.clone();
                let stalled = tokio::spawn(async move {
                    inspection.inspect_final_contents_with_stall(
                        parent, inspected_files, stalled_gate, Duration::from_millis(250),
                        Box::new(move || { let _sent = started.send(()); let _released = wait.recv(); }),
                    ).await
                });
                started_rx.await.unwrap();
                let _timeout = stalled.await.unwrap().unwrap_err();
                let _locked_journal = ExclusiveFile::acquire(&journal_path, journal_id).unwrap_err();
                let file_path = dir.path().join("private/published").join(entries[0].name);
                let _locked_file = ExclusiveFile::acquire(&file_path, entries[0].identity).unwrap_err();
                let _poisoned = inspection_gate.run(Duration::from_secs(1), || Ok(())).await.unwrap_err();
                release.send(()).unwrap();
                let lock = tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        if let Ok(lock) = ExclusiveFile::acquire(&journal_path, journal_id) { break lock; }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }).await.expect("stalled inspection did not release its handles");
                let inspection = LocalInspection::open(lock, &expired).unwrap();
                let parent = parent_after_stall;
                let mut inspected_files = BTreeMap::new();
                for (id, entry) in ids.iter().zip(&entries) {
                    let path = dir.path().join("private/published").join(entry.name);
                    inspected_files.insert((*id).to_owned(), ExclusiveFile::acquire(&path, entry.identity).unwrap());
                }
                let snapshot = inspection.inspect_final_contents_bounded(
                    parent, inspected_files, BlockingIoGate::default(), Duration::from_secs(3),
                ).await.unwrap();
                let _held_journal = ExclusiveFile::acquire(&journal_path, journal_id).unwrap_err();
                let (mut inspection, parent, held_final, mut inspected_files) = snapshot.into_parts();
                assert_eq!(directory_identity(&held_final).unwrap(), stage_id);
                inspection.inspect_final_contents(&parent, &mut inspected_files).unwrap();
                let missing = inspected_files.remove("one").unwrap();
                let _missing = inspection.inspect_final_contents(&parent, &mut inspected_files).unwrap_err();
                inspected_files.insert("one".to_owned(), missing);
                let _wrong_parent = inspection.inspect_final_contents(&published, &mut inspected_files).unwrap_err();
                let extra_path = dir.path().join("private/published/extra.bin");
                std::fs::write(&extra_path, b"extra").unwrap();
                let _extra = inspection.inspect_final_contents(&parent, &mut inspected_files).unwrap_err();
                std::fs::remove_file(&extra_path).unwrap();
                drop(inspected_files);
                std::fs::write(dir.path().join("private/published/one.bin"), b"ONE").unwrap();
                let mut changed_files = BTreeMap::new();
                for (id, entry) in ids.iter().zip(&entries) {
                    let path = dir.path().join("private/published").join(entry.name);
                    changed_files.insert((*id).to_owned(), ExclusiveFile::acquire(&path, entry.identity).unwrap());
                }
                let _changed = inspection.inspect_final_contents(&parent, &mut changed_files).unwrap_err();
                drop(changed_files);
                drop(held_final);
                let moved_path = dir.path().join("private/moved-original");
                std::fs::rename(dir.path().join("private/published"), &moved_path).unwrap();
                let replacement = dir.path().join("private/published");
                std::fs::create_dir(&replacement).unwrap();
                for (name, body) in names.iter().zip(bodies) {
                    std::fs::write(replacement.join(name), body).unwrap();
                }
                let mut original_files = BTreeMap::new();
                for (id, entry) in ids.iter().zip(&entries) {
                    original_files.insert((*id).to_owned(), ExclusiveFile::acquire(&moved_path.join(entry.name), entry.identity).unwrap());
                }
                let replacement_error = inspection.inspect_final_contents(&parent, &mut original_files).unwrap_err();
                assert!(replacement_error.to_string().contains("final directory identity mismatch"));
                drop(original_files);
                drop(inspection);
                assert_eq!(std::fs::read(&journal_path).unwrap(), original_journal);
            } else {
                drop(receiver_state);
                assert!(matches!(control.commit(ID.into(), digest.clone()).await, Err(TransferError::NotReady)));
            }
            for (id, body) in ids.iter().zip(bodies) {
                assert_eq!(std::fs::read(dir.path().join(format!("source-{id}"))).unwrap(), body);
            }
        })).await.expect("protected receiver integration test timed out");
    }

    #[tokio::test]
    async fn timed_out_file_worker_keeps_handle_and_transaction_unavailable() {
        file_worker_interruption(false).await;
    }

    #[tokio::test]
    async fn cancelled_file_worker_keeps_handle_and_transaction_unavailable() {
        file_worker_interruption(true).await;
    }

    async fn file_worker_interruption(cancel: bool) {
        let fixture = fixture(false, false).await;
        let receiver = fixture.receiver.clone();
        let stage_path = fixture.dir.path().join("stage-file");
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let (started, started_rx) = tokio::sync::oneshot::channel::<()>();
        let mut state = receiver.state.lock().await;
        state.deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        state.before_file_io = Some(Box::new(move || {
            let _sent = started.send(());
            let _released = wait.recv();
        }));
        drop(state);
        receiver
            .begin(1, ID.into(), fixture.digest.clone())
            .await
            .unwrap();
        let (_tx, rx) = vox::channel::<Vec<u8>>();
        let upload_receiver = receiver.clone();
        let digest = fixture.digest.clone();
        let upload = tokio::spawn(async move {
            upload_receiver
                .upload(ID.into(), digest, "one".into(), rx)
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), started_rx)
            .await
            .unwrap()
            .unwrap();
        if cancel {
            upload.abort();
            assert!(upload.await.unwrap_err().is_cancelled());
        } else {
            let _error = tokio::time::timeout(Duration::from_secs(3), upload)
                .await
                .unwrap()
                .unwrap()
                .unwrap_err();
        }
        let gate = {
            let state = receiver.state.lock().await;
            assert!(state.in_flight_or_failed);
            assert!(!state.files.contains_key("one"));
            assert!(state.journal.as_ref().unwrap().has_pending_claim("one"));
            state.io_gate.clone()
        };
        let _blocked = std::fs::OpenOptions::new()
            .write(true)
            .open(&stage_path)
            .unwrap_err();
        assert!(gate.run(Duration::from_secs(1), || Ok(())).await.is_err());
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(bytes) = std::fs::read(&stage_path) {
                    assert!(bytes.is_empty());
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("timed-out worker did not release its file after unblocking");
        assert!(gate.run(Duration::from_secs(1), || Ok(())).await.is_err());
        assert_eq!(std::fs::read(&fixture.source).unwrap(), b"hello");
    }

    #[tokio::test]
    async fn rejects_tls_peer_not_bound_to_journal() {
        let fixture = fixture(true, false).await;
        let control = fixture.receiver.clone();
        control.state.lock().await.replay_permit = Some(synthetic_replay_permit());
        control
            .begin(1, ID.into(), fixture.digest.clone())
            .await
            .unwrap();
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
        assert!(matches!(
            control.receipt(ID.into(), fixture.digest.clone()).await,
            Err(TransferError::NotReady)
        ));
        assert_eq!(std::fs::read(&fixture.source).unwrap(), b"hello");
    }

    #[tokio::test]
    async fn rejects_tls_server_not_bound_to_journal() {
        let fixture = fixture(false, true).await;
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
            let fixture = fixture(false, false).await;
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
            assert!(state.journal.as_ref().unwrap().has_pending_claim("one"));
            assert!(!state.journal.as_ref().unwrap().has_observation("one"));
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
            let fixture = fixture(false, false).await;
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
            let fixture = fixture(false, false).await;
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
            assert!(state.journal.as_ref().unwrap().has_pending_claim("one"));
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
