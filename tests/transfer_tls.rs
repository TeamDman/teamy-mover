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
use teamy_mover::transfer::manifest::parse_approved_manifest;
use teamy_mover::transfer::session::BodySetVerifier;
use teamy_mover::transfer::tls::ClientEndpoint;
use teamy_mover::transfer::tls::ServerEndpoint;
use teamy_mover::transfer::vox_transport;
use teamy_mover::transfer::wire::TransferError;
use teamy_mover::transfer::wire::TransferState;
use teamy_mover::transfer::wire::TransferWire;
use teamy_mover::transfer::wire::TransferWireClient;
use teamy_mover::transfer::wire::TransferWireDispatcher;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

struct Fixture {
    root: CertificateDer<'static>,
    server_cert: CertificateDer<'static>,
    server_key: PrivateKeyDer<'static>,
    client_cert: CertificateDer<'static>,
    client_key: PrivateKeyDer<'static>,
}

fn issue(
    issuer: &Issuer<'static, KeyPair>,
    names: Vec<String>,
    usage: ExtendedKeyUsagePurpose,
    expired: bool,
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let mut params = CertificateParams::new(names).unwrap();
    params.extended_key_usages.push(usage);
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    if expired {
        params.not_before = rcgen::date_time_ymd(2000, 1, 1);
        params.not_after = rcgen::date_time_ymd(2001, 1, 1);
    }
    let key = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, issuer).unwrap();
    let private = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    (cert.der().clone(), private)
}

fn fixture(client_usage: ExtendedKeyUsagePurpose, expired_server: bool) -> Fixture {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    ca_params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);
    let (server_cert, server_key) = issue(
        &issuer,
        vec!["100.64.0.1".to_owned()],
        ExtendedKeyUsagePurpose::ServerAuth,
        expired_server,
    );
    let (client_cert, client_key) = issue(&issuer, Vec::new(), client_usage, false);
    Fixture {
        root: ca_cert.der().clone(),
        server_cert,
        server_key,
        client_cert,
        client_key,
    }
}

fn pin(cert: &CertificateDer<'_>) -> [u8; 32] {
    Sha256::digest(cert.as_ref()).into()
}

fn endpoints(
    fixture: Fixture,
    server_name: &'static str,
    bad_server_pin: bool,
    bad_client_pin: bool,
) -> (ClientEndpoint, ServerEndpoint) {
    let server_pin = if bad_server_pin {
        [0; 32]
    } else {
        pin(&fixture.server_cert)
    };
    let client_pin = if bad_client_pin {
        [0; 32]
    } else {
        pin(&fixture.client_cert)
    };
    let client = ClientEndpoint::new(
        vec![fixture.root.clone()],
        vec![fixture.client_cert],
        fixture.client_key,
        ServerName::try_from(server_name.to_owned()).unwrap(),
        server_pin,
    )
    .unwrap();
    let server = ServerEndpoint::new(
        vec![fixture.root],
        vec![fixture.server_cert],
        fixture.server_key,
        client_pin,
    )
    .unwrap();
    (client, server)
}

#[tokio::test]
async fn mutual_tls_accepts_valid_chain_names_and_pins() {
    let (client, server) = endpoints(
        fixture(ExtendedKeyUsagePurpose::ClientAuth, false),
        "100.64.0.1",
        false,
        false,
    );
    let (left, right) = tokio::io::duplex(16384);
    let (client, server) = tokio::join!(client.connect(left), server.accept(right));
    let mut client = client.unwrap();
    let mut server = server.unwrap();
    client.write_all(b"synthetic").await.unwrap();
    let mut received = [0_u8; 9];
    server.read_exact(&mut received).await.unwrap();
    assert_eq!(&received, b"synthetic");
}

#[tokio::test]
async fn rejects_wrong_leaf_pins() {
    let (client, server) = endpoints(
        fixture(ExtendedKeyUsagePurpose::ClientAuth, false),
        "100.64.0.1",
        true,
        false,
    );
    let (left, right) = tokio::io::duplex(16384);
    let (client_result, _) = tokio::join!(client.connect(left), server.accept(right));
    let _error = client_result.unwrap_err();

    let (client, server) = endpoints(
        fixture(ExtendedKeyUsagePurpose::ClientAuth, false),
        "100.64.0.1",
        false,
        true,
    );
    let (left, right) = tokio::io::duplex(16384);
    let (_, server_result) = tokio::join!(client.connect(left), server.accept(right));
    let _error = server_result.unwrap_err();
}

#[tokio::test]
async fn rejects_wrong_server_san_and_expired_server_certificate() {
    for (name, expired) in [("100.64.0.2", false), ("100.64.0.1", true)] {
        let (client, server) = endpoints(
            fixture(ExtendedKeyUsagePurpose::ClientAuth, expired),
            name,
            false,
            false,
        );
        let (left, right) = tokio::io::duplex(16384);
        let (client_result, _) = tokio::join!(client.connect(left), server.accept(right));
        let _error = client_result.unwrap_err();
    }
}

#[tokio::test]
async fn rejects_client_certificate_with_wrong_eku() {
    let (client, server) = endpoints(
        fixture(ExtendedKeyUsagePurpose::ServerAuth, false),
        "100.64.0.1",
        false,
        false,
    );
    let (left, right) = tokio::io::duplex(16384);
    let (_, server_result) = tokio::join!(client.connect(left), server.accept(right));
    let _error = server_result.unwrap_err();
}

#[tokio::test]
async fn rejects_untrusted_server_root() {
    let fixture = fixture(ExtendedKeyUsagePurpose::ClientAuth, false);
    let other = fixture_for_other_root();
    let client = ClientEndpoint::new(
        vec![other],
        vec![fixture.client_cert.clone()],
        fixture.client_key,
        ServerName::try_from("100.64.0.1".to_owned()).unwrap(),
        pin(&fixture.server_cert),
    )
    .unwrap();
    let server = ServerEndpoint::new(
        vec![fixture.root],
        vec![fixture.server_cert],
        fixture.server_key,
        pin(&fixture.client_cert),
    )
    .unwrap();
    let (left, right) = tokio::io::duplex(16384);
    let (client_result, _) = tokio::join!(client.connect(left), server.accept(right));
    let _error = client_result.unwrap_err();
}

fn fixture_for_other_root() -> CertificateDer<'static> {
    fixture(ExtendedKeyUsagePurpose::ClientAuth, false).root
}

#[tokio::test]
async fn rejects_a_client_without_a_certificate() {
    let fixture = fixture(ExtendedKeyUsagePurpose::ClientAuth, false);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(fixture.root.clone()).unwrap();
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let client = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let server = ServerEndpoint::new(
        vec![fixture.root],
        vec![fixture.server_cert],
        fixture.server_key,
        pin(&fixture.client_cert),
    )
    .unwrap();
    let (left, right) = tokio::io::duplex(16384);
    let (_, server_result) = tokio::join!(
        client.connect(ServerName::try_from("100.64.0.1".to_owned()).unwrap(), left),
        server.accept(right)
    );
    let _error = server_result.unwrap_err();
}

#[vox::service]
trait SyntheticEcho {
    async fn echo(&self, value: String) -> String;
}

#[derive(Clone)]
struct SyntheticEchoService;

impl SyntheticEcho for SyntheticEchoService {
    fn echo(&self, value: String) -> impl std::future::Future<Output = String> + Send {
        std::future::ready(value)
    }
}

#[tokio::test]
async fn bounded_vox_exchanges_synthetic_rpc_over_mutual_tls() {
    let (client, server) = endpoints(
        fixture(ExtendedKeyUsagePurpose::ClientAuth, false),
        "100.64.0.1",
        false,
        false,
    );
    let (left, right) = tokio::io::duplex(128 * 1024);
    let (client_tls, server_tls) = tokio::join!(client.connect(left), server.accept(right));
    let (client_vox, server_vox) = tokio::join!(
        vox_transport::establish_client(client_tls.unwrap()),
        vox_transport::establish_server(
            server_tls.unwrap(),
            SyntheticEchoDispatcher::new(SyntheticEchoService)
        )
    );
    let client_vox = client_vox.unwrap();
    let _server_vox = server_vox.unwrap();
    let lane: SyntheticEchoClient = client_vox.open_lane().await.unwrap();
    assert_eq!(lane.echo("synthetic".into()).await.unwrap(), "synthetic");
}

#[cfg(windows)]
#[vox::service]
trait BlockingGateProbe {
    async fn upload(&self, chunks: vox::Rx<Vec<u8>>) -> Result<(), TransferError>;
}

#[cfg(windows)]
#[derive(Clone, Default)]
struct BlockingGateService {
    gate: teamy_mover::transfer::blocking_io::BlockingIoGate,
    progress: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    use_timer: bool,
}

#[cfg(windows)]
impl BlockingGateProbe for BlockingGateService {
    async fn upload(&self, mut chunks: vox::Rx<Vec<u8>>) -> Result<(), TransferError> {
        use std::sync::atomic::Ordering;
        self.progress.fetch_or(1, Ordering::SeqCst);
        if self.use_timer {
            self.progress.fetch_or(2, Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            self.progress.fetch_or(4, Ordering::SeqCst);
        } else {
            let progress = std::sync::Arc::clone(&self.progress);
            self.gate
                .run(std::time::Duration::from_secs(2), move || {
                    progress.fetch_or(2, Ordering::SeqCst);
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    progress.fetch_or(4, Ordering::SeqCst);
                    Ok(())
                })
                .await
                .map_err(|_error| TransferError::Failed)?;
        }
        self.progress.fetch_or(8, Ordering::SeqCst);
        let mut count = 0usize;
        while let Some(chunk) = chunks
            .recv()
            .await
            .map_err(|_error| TransferError::Failed)?
        {
            count += chunk.get().len();
            self.progress.fetch_or(16, Ordering::SeqCst);
        }
        self.progress.fetch_or(32, Ordering::SeqCst);
        if count == 5 {
            Ok(())
        } else {
            Err(TransferError::Rejected)
        }
    }
}

#[cfg(windows)]
async fn gate_probe(use_timer: bool) {
    use std::sync::atomic::Ordering;
    let service = BlockingGateService {
        use_timer,
        ..BlockingGateService::default()
    };
    let progress = std::sync::Arc::clone(&service.progress);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let (client, server) = endpoints(
            fixture(ExtendedKeyUsagePurpose::ClientAuth, false),
            "100.64.0.1",
            false,
            false,
        );
        let (left, right) = tokio::io::duplex(128 * 1024);
        let (client_tls, server_tls) = tokio::join!(client.connect(left), server.accept(right));
        let (client_vox, server_vox) = tokio::join!(
            vox_transport::establish_client(client_tls.unwrap()),
            vox_transport::establish_server(
                server_tls.unwrap(),
                BlockingGateProbeDispatcher::new(service)
            )
        );
        let client_vox = client_vox.unwrap();
        let _server_vox = server_vox.unwrap();
        let lane: BlockingGateProbeClient = client_vox.open_lane().await.unwrap();
        let (tx, rx) = vox::channel::<Vec<u8>>();
        let upload = lane.upload(rx);
        let send = async move {
            tx.send(b"he".to_vec()).await.unwrap();
            tx.close(vox::Metadata::default()).await.unwrap();
        };
        let (result, ()) = tokio::join!(upload, send);
        let _error = result.unwrap_err();
    })
    .await;
    outcome.unwrap_or_else(|_| {
        panic!(
            "channel handler did not resume; progress bits {}",
            progress.load(Ordering::SeqCst)
        )
    });
}

#[cfg(windows)]
#[tokio::test]
async fn incomplete_channel_closes_after_blocking_gate() {
    gate_probe(false).await;
}

#[cfg(windows)]
#[tokio::test]
async fn incomplete_channel_closes_after_async_timer() {
    gate_probe(true).await;
}

#[cfg(windows)]
#[vox::service]
trait TimerOnlyProbe {
    async fn wait(&self) -> bool;
}

#[cfg(windows)]
#[derive(Clone)]
struct TimerOnlyService;

#[cfg(windows)]
impl TimerOnlyProbe for TimerOnlyService {
    async fn wait(&self) -> bool {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        true
    }
}

#[cfg(windows)]
#[tokio::test]
async fn timer_without_channel_completes() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let (client, server) = endpoints(
            fixture(ExtendedKeyUsagePurpose::ClientAuth, false),
            "100.64.0.1",
            false,
            false,
        );
        let (left, right) = tokio::io::duplex(128 * 1024);
        let (client_tls, server_tls) = tokio::join!(client.connect(left), server.accept(right));
        let (client_vox, server_vox) = tokio::join!(
            vox_transport::establish_client(client_tls.unwrap()),
            vox_transport::establish_server(
                server_tls.unwrap(),
                TimerOnlyProbeDispatcher::new(TimerOnlyService)
            )
        );
        let client_vox = client_vox.unwrap();
        let _server_vox = server_vox.unwrap();
        let lane: TimerOnlyProbeClient = client_vox.open_lane().await.unwrap();
        assert!(lane.wait().await.unwrap());
    })
    .await
    .expect("timer-only probe timed out");
}

const TRANSACTION_ID: &str = "0123456789abcdef0123456789abcdef";

struct MemoryTransferState {
    began: bool,
    bodies: BodySetVerifier<Vec<u8>>,
}

#[derive(Clone)]
struct MemoryTransfer {
    manifest_digest: String,
    #[cfg(any(windows, target_os = "linux"))]
    manifest_bytes: Vec<u8>,
    #[cfg(any(windows, target_os = "linux"))]
    reject_upload: bool,
    state: std::sync::Arc<tokio::sync::Mutex<MemoryTransferState>>,
}

impl MemoryTransfer {
    fn new() -> Self {
        Self::with_expiry(100)
    }

    fn with_expiry(expiry: u64) -> Self {
        let first = format!("{:x}", Sha256::digest(b"hello"));
        let second = format!("{:x}", Sha256::digest(b"world"));
        let raw = format!(
            r#"{{"aggregate_bytes":10,"expires_unix":{expiry},"file_count":2,"files":[{{"id":"one","name":"a.bin","sha256":"{first}","size":5}},{{"id":"two","name":"b.bin","sha256":"{second}","size":5}}],"transaction_id":"{TRANSACTION_ID}","version":1}}"#
        );
        Self::from_manifest(raw)
    }

    #[cfg(any(windows, target_os = "linux"))]
    fn three_with_expiry(expiry: u64) -> Self {
        let first = format!("{:x}", Sha256::digest(b"hello"));
        let second = format!("{:x}", Sha256::digest(b"world"));
        let third = format!("{:x}", Sha256::digest(b"extra"));
        let raw = format!(
            r#"{{"aggregate_bytes":15,"expires_unix":{expiry},"file_count":3,"files":[{{"id":"one","name":"a.bin","sha256":"{first}","size":5}},{{"id":"two","name":"b.bin","sha256":"{second}","size":5}},{{"id":"three","name":"c.bin","sha256":"{third}","size":5}}],"transaction_id":"{TRANSACTION_ID}","version":1}}"#
        );
        Self::from_manifest(raw)
    }

    fn from_manifest(raw: String) -> Self {
        let digest = format!("{:x}", Sha256::digest(raw.as_bytes()));
        let manifest = parse_approved_manifest(raw.as_bytes(), &digest, TRANSACTION_ID, 1).unwrap();
        Self {
            manifest_digest: digest,
            #[cfg(any(windows, target_os = "linux"))]
            manifest_bytes: raw.into_bytes(),
            #[cfg(any(windows, target_os = "linux"))]
            reject_upload: false,
            state: std::sync::Arc::new(tokio::sync::Mutex::new(MemoryTransferState {
                began: false,
                bodies: BodySetVerifier::new(manifest, 1).unwrap(),
            })),
        }
    }

    fn matches(&self, transaction_id: &str, manifest_sha256: &str) -> bool {
        transaction_id == TRANSACTION_ID && manifest_sha256 == self.manifest_digest
    }
}

impl TransferWire for MemoryTransfer {
    async fn begin(
        &self,
        version: u32,
        transaction_id: String,
        manifest_sha256: String,
    ) -> Result<(), TransferError> {
        if version != 1 || !self.matches(&transaction_id, &manifest_sha256) {
            return Err(TransferError::Rejected);
        }
        let mut state = self.state.lock().await;
        if state.began {
            return Err(TransferError::Rejected);
        }
        state.began = true;
        Ok(())
    }

    async fn upload(
        &self,
        transaction_id: String,
        manifest_sha256: String,
        file_id: String,
        mut chunks: vox::Rx<Vec<u8>>,
    ) -> Result<(), TransferError> {
        if !self.matches(&transaction_id, &manifest_sha256) {
            return Err(TransferError::Rejected);
        }
        #[cfg(any(windows, target_os = "linux"))]
        if self.reject_upload {
            return Err(TransferError::Failed);
        }
        let mut state = self.state.lock().await;
        if !state.began {
            return Err(TransferError::NotReady);
        }
        state
            .bodies
            .begin(&file_id, Vec::new(), 1)
            .map_err(|_error| TransferError::Rejected)?;
        while let Some(chunk) = chunks
            .recv()
            .await
            .map_err(|_error| TransferError::Failed)?
        {
            state
                .bodies
                .push(chunk.get(), 1)
                .map_err(|_error| TransferError::Rejected)?;
        }
        let _output = state
            .bodies
            .finish(1)
            .map_err(|_error| TransferError::Rejected)?;
        Ok(())
    }

    async fn status(
        &self,
        transaction_id: String,
        manifest_sha256: String,
    ) -> Result<TransferState, TransferError> {
        if !self.matches(&transaction_id, &manifest_sha256) {
            return Err(TransferError::Rejected);
        }
        let mut state = self.state.lock().await;
        if !state.began {
            return Ok(TransferState::AwaitingBegin);
        }
        if state.bodies.all_bodies_checked(1) {
            Ok(TransferState::BodiesChecked)
        } else {
            Ok(TransferState::Receiving)
        }
    }

    fn receipt(
        &self,
        transaction_id: String,
        manifest_sha256: String,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, TransferError>> + Send {
        let result = if self.matches(&transaction_id, &manifest_sha256) {
            Err(TransferError::NotReady)
        } else {
            Err(TransferError::Rejected)
        };
        std::future::ready(result)
    }

    fn commit(
        &self,
        transaction_id: String,
        manifest_sha256: String,
    ) -> impl std::future::Future<Output = Result<(), TransferError>> + Send {
        // This synthetic service cannot publish and must not report success.
        let result = if self.matches(&transaction_id, &manifest_sha256) {
            Err(TransferError::NotReady)
        } else {
            Err(TransferError::Rejected)
        };
        std::future::ready(result)
    }
}

#[tokio::test]
async fn transfer_contract_streams_synthetic_bodies_over_pinned_tls_and_vox() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let service = MemoryTransfer::new();
        let digest = service.manifest_digest.clone();
        let (client, server) = endpoints(
            fixture(ExtendedKeyUsagePurpose::ClientAuth, false),
            "100.64.0.1",
            false,
            false,
        );
        let (left, right) = tokio::io::duplex(128 * 1024);
        let (client_tls, server_tls) = tokio::join!(client.connect(left), server.accept(right));
        let (client_vox, server_vox) = tokio::join!(
            vox_transport::establish_client(client_tls.unwrap()),
            vox_transport::establish_server(
                server_tls.unwrap(),
                TransferWireDispatcher::new(service)
            )
        );
        let client_vox = client_vox.unwrap();
        let _server_vox = server_vox.unwrap();
        let lane: TransferWireClient = client_vox.open_lane().await.unwrap();
        let rejected = lane
            .begin(1, TRANSACTION_ID.to_owned(), "wrong".to_owned())
            .await;
        assert!(
            matches!(rejected, Err(vox::VoxError::User(error)) if *error == TransferError::Rejected)
        );
        lane.begin(1, TRANSACTION_ID.to_owned(), digest.clone())
            .await
            .unwrap();
        for (id, body) in [("one", b"hello".as_slice()), ("two", b"world".as_slice())] {
            let (tx, rx) = vox::channel::<Vec<u8>>();
            let upload = lane.upload(TRANSACTION_ID.to_owned(), digest.clone(), id.to_owned(), rx);
            let send = async move {
                tx.send(body[..2].to_vec()).await.unwrap();
                tx.send(body[2..].to_vec()).await.unwrap();
                tx.close(vox::Metadata::default()).await.unwrap();
            };
            let (result, ()) = tokio::join!(upload, send);
            result.unwrap();
        }
        assert_eq!(
            lane.status(TRANSACTION_ID.to_owned(), digest.clone())
                .await
                .unwrap(),
            TransferState::BodiesChecked
        );
        let commit = lane.commit(TRANSACTION_ID.to_owned(), digest).await;
        assert!(
            matches!(commit, Err(vox::VoxError::User(error)) if *error == TransferError::NotReady)
        );
    })
    .await
    .expect("in-memory transfer contract timed out");
}

#[cfg(any(windows, target_os = "linux"))]
fn test_source(id: &str, path: &std::path::Path) -> teamy_mover::transfer::sender::Source {
    #[cfg(windows)]
    {
        teamy_mover::transfer::sender::Source::from_file(
            id.into(),
            std::fs::File::open(path).unwrap(),
        )
    }
    #[cfg(target_os = "linux")]
    {
        teamy_mover::transfer::sender::Source::open(id.into(), path).unwrap()
    }
}

#[cfg(any(windows, target_os = "linux"))]
async fn sender_fixture() -> (
    vox_transport::BoundedConnection,
    vox_transport::BoundedConnection,
    MemoryTransfer,
) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let service = MemoryTransfer::with_expiry(now + 600);
    let (client, server) = endpoints(
        fixture(ExtendedKeyUsagePurpose::ClientAuth, false),
        "100.64.0.1",
        false,
        false,
    );
    let (left, right) = tokio::io::duplex(128 * 1024);
    let (client_tls, server_tls) = tokio::join!(client.connect(left), server.accept(right));
    let (client_vox, server_vox) = tokio::join!(
        vox_transport::establish_client(client_tls.unwrap()),
        vox_transport::establish_server(
            server_tls.unwrap(),
            TransferWireDispatcher::new(service.clone())
        )
    );
    (client_vox.unwrap(), server_vox.unwrap(), service)
}

#[cfg(any(windows, target_os = "linux"))]
#[tokio::test]
async fn production_sender_preserves_sources_when_receiver_fails() {
    use teamy_mover::transfer::sender::send_prepublication;
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut service = MemoryTransfer::with_expiry(now + 600);
        service.reject_upload = true;
        let (client, server) = endpoints(
            fixture(ExtendedKeyUsagePurpose::ClientAuth, false),
            "100.64.0.1",
            false,
            false,
        );
        let (left, right) = tokio::io::duplex(128 * 1024);
        let (client_tls, server_tls) = tokio::join!(client.connect(left), server.accept(right));
        let (client_vox, server_vox) = tokio::join!(
            vox_transport::establish_client(client_tls.unwrap()),
            vox_transport::establish_server(
                server_tls.unwrap(),
                TransferWireDispatcher::new(service.clone())
            )
        );
        let client_vox = client_vox.unwrap();
        let _server_vox = server_vox.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::write(&a, b"hello").unwrap();
        std::fs::write(&b, b"world").unwrap();
        let sources = vec![test_source("one", &a), test_source("two", &b)];
        assert!(
            send_prepublication(
                &client_vox,
                &service.manifest_bytes,
                &service.manifest_digest,
                TRANSACTION_ID,
                sources
            )
            .await
            .is_err()
        );
        assert_eq!(std::fs::read(&a).unwrap(), b"hello");
        assert_eq!(std::fs::read(&b).unwrap(), b"world");
    })
    .await
    .expect("sender failure test timed out");
}

#[cfg(any(windows, target_os = "linux"))]
#[tokio::test]
async fn production_sender_streams_files_over_pinned_tls_without_deleting_sources() {
    use teamy_mover::transfer::sender::send_prepublication;
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let (client, _server, service) = sender_fixture().await;
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::write(&a, b"hello").unwrap();
        std::fs::write(&b, b"world").unwrap();
        let sources = vec![test_source("two", &b), test_source("one", &a)];
        send_prepublication(
            &client,
            &service.manifest_bytes,
            &service.manifest_digest,
            TRANSACTION_ID,
            sources,
        )
        .await
        .unwrap();
        assert_eq!(std::fs::read(&a).unwrap(), b"hello");
        assert_eq!(std::fs::read(&b).unwrap(), b"world");
        assert!(service.state.lock().await.bodies.all_bodies_checked(1));
    })
    .await
    .expect("sender test timed out");
}

#[cfg(any(windows, target_os = "linux"))]
async fn read_connect_request(stream: &mut tokio::io::DuplexStream) -> Vec<u8> {
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        assert!(request.len() < 8192, "CONNECT headers exceeded test limit");
        request.push(stream.read_u8().await.unwrap());
    }
    request
}

#[cfg(any(windows, target_os = "linux"))]
#[tokio::test]
async fn sender_streams_verified_sources_through_connect_and_pinned_tls() {
    use teamy_mover::transfer::sender::send_prepublication_via_proxy;

    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let service = MemoryTransfer::three_with_expiry(now + 600);
        let (client, server) = endpoints(
            fixture(ExtendedKeyUsagePurpose::ClientAuth, false),
            "100.64.0.1",
            false,
            false,
        );
        let (left, mut right) = tokio::io::duplex(128 * 1024);
        let dispatcher = TransferWireDispatcher::new(service.clone());
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel::<()>();
        let proxy_and_server = async move {
            let request = read_connect_request(&mut right).await;
            assert!(request.starts_with(b"CONNECT 100.64.0.1:49152 HTTP/1.1\r\n"));
            right
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            let authenticated = server.accept(right).await.unwrap();
            let _server_vox = vox_transport::establish_server(authenticated, dispatcher)
                .await
                .unwrap();
            let _finished = finished_rx.await;
        };
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("a");
        let second = dir.path().join("b");
        let third = dir.path().join("c");
        std::fs::write(&first, b"hello").unwrap();
        std::fs::write(&second, b"world").unwrap();
        std::fs::write(&third, b"extra").unwrap();
        let sender = async {
            let result = send_prepublication_via_proxy(
                left,
                "100.64.0.1:49152",
                &client,
                &service.manifest_bytes,
                &service.manifest_digest,
                TRANSACTION_ID,
                vec![
                    test_source("one", &first),
                    test_source("two", &second),
                    test_source("three", &third),
                ],
            )
            .await;
            let _sent = finished_tx.send(());
            result
        };
        let (sent, ()) = tokio::join!(sender, proxy_and_server);
        sent.unwrap();
        assert_eq!(std::fs::read(first).unwrap(), b"hello");
        assert_eq!(std::fs::read(second).unwrap(), b"world");
        assert_eq!(std::fs::read(third).unwrap(), b"extra");
        assert!(service.state.lock().await.bodies.all_bodies_checked(1));
    })
    .await
    .expect("synthetic CONNECT transfer timed out");
}

#[cfg(any(windows, target_os = "linux"))]
#[tokio::test]
async fn connect_denial_stops_before_tls_and_has_no_fallback() {
    let (client, _server) = endpoints(
        fixture(ExtendedKeyUsagePurpose::ClientAuth, false),
        "100.64.0.1",
        false,
        false,
    );
    let (left, mut right) = tokio::io::duplex(16 * 1024);
    let proxy = async move {
        let request = read_connect_request(&mut right).await;
        assert!(request.starts_with(b"CONNECT 100.64.0.1:49152 HTTP/1.1\r\n"));
        right
            .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        let mut byte = [0_u8; 1];
        let count = tokio::time::timeout(std::time::Duration::from_secs(2), right.read(&mut byte))
            .await
            .expect("client did not close denied tunnel")
            .unwrap();
        assert_eq!(count, 0, "TLS data was sent after CONNECT denial");
    };
    let (result, ()) = tokio::join!(
        vox_transport::establish_client_via_proxy(left, "100.64.0.1:49152", &client),
        proxy
    );
    assert!(result.unwrap_err().to_string().contains("HTTP 503"));
}

#[cfg(any(windows, target_os = "linux"))]
#[tokio::test]
async fn production_sender_rejects_bad_source_before_contacting_receiver() {
    use teamy_mover::transfer::sender::send_prepublication;
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let (client, _server, service) = sender_fixture().await;
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::write(&a, b"HELLO").unwrap();
        std::fs::write(&b, b"world").unwrap();
        let sources = vec![test_source("one", &a), test_source("two", &b)];
        assert!(
            send_prepublication(
                &client,
                &service.manifest_bytes,
                &service.manifest_digest,
                TRANSACTION_ID,
                sources
            )
            .await
            .is_err()
        );
        assert!(!service.state.lock().await.began);
        assert_eq!(std::fs::read(&a).unwrap(), b"HELLO");
        assert_eq!(std::fs::read(&b).unwrap(), b"world");
    })
    .await
    .expect("sender test timed out");
}
