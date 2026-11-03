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
    async fn echo(&self, value: String) -> String {
        value
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

    async fn commit(
        &self,
        transaction_id: String,
        manifest_sha256: String,
    ) -> Result<(), TransferError> {
        if !self.matches(&transaction_id, &manifest_sha256) {
            return Err(TransferError::Rejected);
        }
        // This synthetic service cannot publish and must not report success.
        Err(TransferError::NotReady)
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
