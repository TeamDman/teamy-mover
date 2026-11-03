#![cfg(windows)]

//! Manually run against the normal receiver binary, using temporary fixtures and
//! the user's explicitly approved Tailscale-only address. No cloud data is used.

use facet::Facet;
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use teamy_mover::transfer::journal::{JournalApproval, ObjectIdentity};
use teamy_mover::transfer::recovery::RecoveryDisposition;
use teamy_mover::transfer::sender::{Source, send_approved_and_commit};
use teamy_mover::transfer::tls::ClientEndpoint;
use teamy_mover::transfer::transaction_journal::LocalInspection;
use teamy_mover::transfer::vox_transport;
use teamy_mover::transfer::windows_lock::{
    ExclusiveFile, directory_identity, regular_file_identity,
};
use teamy_mover::transfer::wire::TransferState;
use windows::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL,
    SYNCHRONIZE,
};

const ID: &str = "0123456789abcdef0123456789abcdef";
const IDS: [&str; 3] = ["one", "two", "three"];
const BODIES: [&[u8]; 3] = [b"one", b"two", b"three"];

#[derive(Facet)]
struct Config {
    version: u32,
    manifest_file: String,
    manifest_sha256: String,
    transaction_id: String,
    server_certificate_der: String,
    server_key_der: String,
    client_certificate_der: String,
    server_sha256: String,
    client_sha256: String,
    target: String,
    work_parent: String,
    destination_parent: String,
    final_name: String,
}

struct StopChild(Child);
impl Drop for StopChild {
    fn drop(&mut self) {
        let _killed = self.0.kill();
        let _waited = self.0.wait();
    }
}

fn sid_text() -> String {
    use std::fmt::Write as _;
    let sid = teamy_mover::transfer::windows_acl::process_user_sid().unwrap();
    let authority = sid[2..8]
        .iter()
        .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte));
    let mut result = format!("S-{}-{authority}", sid[0]);
    for part in sid[8..].chunks_exact(4) {
        write!(
            &mut result,
            "-{}",
            u32::from_le_bytes(part.try_into().unwrap())
        )
        .unwrap();
    }
    result
}

fn secure_acl(path: &Path, inherit: bool) {
    let flags = if inherit { "(OI)(CI)" } else { "" };
    let output = Command::new("icacls")
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(format!("*{}:{flags}(F)", sid_text()))
        .arg(format!("*S-1-5-18:{flags}(F)"))
        .arg(format!("*S-1-5-32-544:{flags}(F)"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "synthetic ACL setup failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn issue_self_signed(
    name: &str,
    purpose: ExtendedKeyUsagePurpose,
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
    params.extended_key_usages.push(purpose);
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    (
        cert.der().clone(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
}

struct Fixture {
    dir: tempfile::TempDir,
    profile: PathBuf,
    config_path: PathBuf,
    manifest: Vec<u8>,
    digest: String,
    client_pin: String,
    server_pin: String,
    client: ClientEndpoint,
    sources: Vec<PathBuf>,
    target: std::net::SocketAddrV4,
}

impl Fixture {
    fn new() -> Self {
        Self::with_expiry(120)
    }

    fn with_expiry(seconds: u64) -> Self {
        let target: std::net::SocketAddrV4 = std::env::var("TEAMY_TEST_TAILNET_TARGET")
            .expect("select the approved test target")
            .parse()
            .unwrap();
        let octets = target.ip().octets();
        assert_eq!(octets[0], 100);
        assert_eq!(octets[1] & 0xc0, 0x40);
        assert_eq!(target.port(), 49152);
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path().join("profile");
        std::fs::create_dir(&profile).unwrap();
        secure_acl(&profile, true);
        let downloads = profile.join("Downloads");
        std::fs::create_dir(&downloads).unwrap();
        let output = Command::new("icacls")
            .arg(&downloads)
            .args(["/grant", "*S-1-1-0:(OI)(CI)(M)"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let (server_cert, server_key) = issue_self_signed(
            &target.ip().to_string(),
            ExtendedKeyUsagePurpose::ServerAuth,
        );
        let (client_cert, client_key) =
            issue_self_signed("test-client", ExtendedKeyUsagePurpose::ClientAuth);
        let server_pin_bytes: [u8; 32] = Sha256::digest(server_cert.as_ref()).into();
        let server_pin = format!("{:x}", Sha256::digest(server_cert.as_ref()));
        let client_pin = format!("{:x}", Sha256::digest(client_cert.as_ref()));
        let server_path = dir.path().join("server.der");
        let client_path = dir.path().join("client.der");
        let key_path = dir.path().join("server.pk8");
        std::fs::write(&server_path, server_cert.as_ref()).unwrap();
        std::fs::write(&client_path, client_cert.as_ref()).unwrap();
        let PrivateKeyDer::Pkcs8(key) = server_key else {
            panic!("PKCS8 required")
        };
        std::fs::write(&key_path, key.secret_pkcs8_der()).unwrap();
        secure_acl(&key_path, false);
        let client = ClientEndpoint::new(
            vec![server_cert],
            vec![client_cert],
            client_key,
            ServerName::from(std::net::IpAddr::V4(*target.ip())),
            server_pin_bytes,
        )
        .unwrap();
        let mut entries = Vec::new();
        let mut sources = Vec::new();
        for (id, body) in IDS.iter().zip(BODIES) {
            let path = dir.path().join(format!("source-{id}"));
            std::fs::write(&path, body).unwrap();
            sources.push(path);
            let hash = format!("{:x}", Sha256::digest(body));
            entries.push(format!(
                r#"{{"id":"{id}","name":"{id}.bin","sha256":"{hash}","size":{}}}"#,
                body.len()
            ));
        }
        let expiry = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + seconds;
        let manifest = format!(r#"{{"aggregate_bytes":11,"expires_unix":{expiry},"file_count":3,"files":[{}],"transaction_id":"{ID}","version":1}}"#, entries.join(",")).into_bytes();
        let digest = format!("{:x}", Sha256::digest(&manifest));
        let manifest_path = dir.path().join("manifest.json");
        std::fs::write(&manifest_path, &manifest).unwrap();
        let config = Config {
            version: 1,
            manifest_file: manifest_path.to_string_lossy().into_owned(),
            manifest_sha256: digest.clone(),
            transaction_id: ID.to_owned(),
            server_certificate_der: server_path.to_string_lossy().into_owned(),
            server_key_der: key_path.to_string_lossy().into_owned(),
            client_certificate_der: client_path.to_string_lossy().into_owned(),
            server_sha256: server_pin.clone(),
            client_sha256: client_pin.clone(),
            target: target.to_string(),
            work_parent: profile.to_string_lossy().into_owned(),
            destination_parent: downloads.to_string_lossy().into_owned(),
            final_name: "storytelling-recovery".to_owned(),
        };
        let config_path = dir.path().join("receive.json");
        std::fs::write(&config_path, facet_json::to_string(&config).unwrap()).unwrap();
        Self {
            dir,
            profile,
            config_path,
            manifest,
            digest,
            client_pin,
            server_pin,
            client,
            sources,
            target,
        }
    }

    fn start(&self) -> StopChild {
        StopChild(
            Command::new(env!("CARGO_BIN_EXE_teamy-mover"))
                .args([
                    "--output-format",
                    "json",
                    "transfer",
                    "receive",
                    "--config-file",
                ])
                .arg(&self.config_path)
                .env("USERPROFILE", &self.profile)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        )
    }

    async fn connect(&self, child: &mut StopChild) -> tokio::net::TcpStream {
        tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                if let Ok(socket) = tokio::net::TcpStream::connect(self.target).await {
                    break socket;
                }
                if let Some(status) = child.0.try_wait().unwrap() {
                    let mut error = String::new();
                    child
                        .0
                        .stderr
                        .take()
                        .unwrap()
                        .read_to_string(&mut error)
                        .unwrap();
                    panic!("receiver exited before listen ({status}): {error}");
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("receiver did not listen")
    }

    async fn wait(&self, child: &mut StopChild) -> (std::process::ExitStatus, String, String) {
        let status = tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                if let Some(status) = child.0.try_wait().unwrap() {
                    break status;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("receiver did not exit");
        let mut stdout = String::new();
        let mut stderr = String::new();
        child
            .0
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut stdout)
            .unwrap();
        child
            .0
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        (status, stdout, stderr)
    }

    fn sources(&self) -> Vec<Source> {
        IDS.iter()
            .zip(&self.sources)
            .map(|(id, path)| Source::from_file((*id).to_owned(), File::open(path).unwrap()))
            .collect()
    }

    fn assert_sources(&self) {
        for (path, body) in self.sources.iter().zip(BODIES) {
            assert_eq!(std::fs::read(path).unwrap(), body);
        }
    }

    fn inspect_published(&self) -> eyre::Result<()> {
        let final_path = self.profile.join("Downloads/storytelling-recovery");
        let parent = open_directory(&self.profile.join("Downloads"));
        let final_dir = open_directory(&final_path);
        let parent_id = directory_identity(&parent).unwrap();
        let final_id = directory_identity(&final_dir).unwrap();
        let journal_path = self.profile.join(format!("storytelling-{ID}/journal.bin"));
        let journal_id = regular_file_identity(&File::open(&journal_path).unwrap()).unwrap();
        let object = |id: teamy_mover::transfer::windows_lock::FileIdentity| ObjectIdentity {
            volume_serial: id.volume_serial,
            file_index: id.file_index,
        };
        let approval = JournalApproval {
            manifest_bytes: &self.manifest,
            manifest_sha256: &self.digest,
            transaction_id: ID,
            client_pin: &self.client_pin,
            server_pin: &self.server_pin,
            destination_parent: object(parent_id),
            stage_directory: object(final_id),
            journal_file: object(journal_id),
            final_name: "storytelling-recovery",
            now_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        let lock = ExclusiveFile::acquire(&journal_path, journal_id).unwrap();
        let mut inspection = LocalInspection::open(lock, &approval).unwrap();
        assert_eq!(
            inspection.disposition(),
            RecoveryDisposition::InspectPublished
        );
        assert!(inspection.intent_matches_directory(&final_dir).unwrap());
        let mut files = BTreeMap::new();
        for id in IDS {
            let path = final_path.join(format!("{id}.bin"));
            let identity = regular_file_identity(&File::open(&path).unwrap()).unwrap();
            files.insert(
                id.to_owned(),
                ExclusiveFile::acquire(&path, identity).unwrap(),
            );
        }
        inspection.inspect_final_contents(&parent, &mut files)
    }
}

fn open_directory(path: &Path) -> File {
    std::fs::OpenOptions::new()
        .access_mode((FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE).0)
        .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
        .unwrap()
}

#[tokio::test]
#[ignore = "manual non-test receiver over approved Tailscale-only address"]
async fn production_receiver_publishes_and_reconciles_synthetic_files() {
    let fixture = Fixture::new();
    let mut child = fixture.start();
    let socket = fixture.connect(&mut child).await;
    let tls = fixture.client.connect(socket).await.unwrap();
    let connection = vox_transport::establish_client(tls).await.unwrap();
    let state = send_approved_and_commit(
        &connection,
        &fixture.manifest,
        &fixture.digest,
        ID,
        fixture.sources(),
    )
    .await
    .unwrap();
    assert_eq!(state, TransferState::PublishedDurabilityUnconfirmed);
    connection.shutdown().unwrap();
    let (status, stdout, stderr) = fixture.wait(&mut child).await;
    assert!(status.success(), "receiver failed: {stderr}");
    assert!(stdout.contains("published-durability-unconfirmed"));
    fixture.assert_sources();
    for (id, body) in IDS.iter().zip(BODIES) {
        assert_eq!(
            std::fs::read(
                fixture
                    .profile
                    .join("Downloads/storytelling-recovery")
                    .join(format!("{id}.bin"))
            )
            .unwrap(),
            body
        );
    }
    fixture.inspect_published().unwrap();
    let first = fixture
        .profile
        .join("Downloads/storytelling-recovery/one.bin");
    std::fs::write(&first, b"ONE").unwrap();
    let _changed_hash = fixture.inspect_published().unwrap_err();
    std::fs::write(&first, b"one").unwrap();
    let mut stream = first.into_os_string();
    stream.push(":unexpected");
    std::fs::write(PathBuf::from(stream), b"hidden").unwrap();
    let _changed_stream = fixture.inspect_published().unwrap_err();
}

#[tokio::test]
#[ignore = "manual non-test receiver collision over approved Tailscale-only address"]
async fn production_receiver_never_overwrites_existing_destination() {
    let fixture = Fixture::new();
    let destination = fixture.profile.join("Downloads/storytelling-recovery");
    std::fs::create_dir(&destination).unwrap();
    std::fs::write(destination.join("marker"), b"original").unwrap();
    let mut child = fixture.start();
    let socket = fixture.connect(&mut child).await;
    let tls = fixture.client.connect(socket).await.unwrap();
    let connection = vox_transport::establish_client(tls).await.unwrap();
    let _rejected = send_approved_and_commit(
        &connection,
        &fixture.manifest,
        &fixture.digest,
        ID,
        fixture.sources(),
    )
    .await
    .unwrap_err();
    let _shutdown = connection.shutdown();
    let (status, _stdout, _stderr) = fixture.wait(&mut child).await;
    assert!(!status.success());
    assert_eq!(
        std::fs::read(destination.join("marker")).unwrap(),
        b"original"
    );
    fixture.assert_sources();
}

#[tokio::test]
#[ignore = "manual non-test receiver disconnect over approved Tailscale-only address"]
async fn production_receiver_disconnect_preserves_stage_and_sources() {
    let fixture = Fixture::new();
    let mut child = fixture.start();
    let socket = fixture.connect(&mut child).await;
    let tls = fixture.client.connect(socket).await.unwrap();
    drop(tls);
    let (status, _stdout, _stderr) = fixture.wait(&mut child).await;
    assert!(!status.success());
    assert!(
        !fixture
            .profile
            .join("Downloads/storytelling-recovery")
            .exists()
    );
    assert!(
        fixture
            .profile
            .join(format!("storytelling-{ID}/journal.bin"))
            .is_file()
    );
    fixture.assert_sources();
}

#[tokio::test]
#[ignore = "manual non-test receiver authentication over approved Tailscale-only address"]
async fn production_receiver_rejects_unapproved_client_certificate() {
    let fixture = Fixture::new();
    let (wrong_cert, wrong_key) =
        issue_self_signed("wrong-client", ExtendedKeyUsagePurpose::ClientAuth);
    let server_bytes = std::fs::read(fixture.dir.path().join("server.der")).unwrap();
    let server_pin: [u8; 32] = Sha256::digest(&server_bytes).into();
    let wrong = ClientEndpoint::new(
        vec![CertificateDer::from(server_bytes)],
        vec![wrong_cert],
        wrong_key,
        ServerName::from(std::net::IpAddr::V4(*fixture.target.ip())),
        server_pin,
    )
    .unwrap();
    let mut child = fixture.start();
    let socket = fixture.connect(&mut child).await;
    if let Ok(stream) = wrong.connect(socket).await {
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            vox_transport::establish_client(stream),
        )
        .await
        .expect("bad client did not terminate");
        let _rejected = result.unwrap_err();
    }
    let (status, _stdout, _stderr) = fixture.wait(&mut child).await;
    assert!(!status.success());
    assert!(
        !fixture
            .profile
            .join("Downloads/storytelling-recovery")
            .exists()
    );
    fixture.assert_sources();
}

#[tokio::test]
#[ignore = "manual non-test receiver deadline on approved Tailscale-only address"]
async fn production_receiver_expires_without_a_client() {
    let fixture = Fixture::with_expiry(4);
    let mut child = fixture.start();
    let (status, _stdout, stderr) = fixture.wait(&mut child).await;
    assert!(!status.success());
    assert!(
        stderr.contains("deadline expired"),
        "unexpected failure: {stderr}"
    );
    assert!(
        !fixture
            .profile
            .join("Downloads/storytelling-recovery")
            .exists()
    );
    assert!(
        fixture
            .profile
            .join(format!("storytelling-{ID}/journal.bin"))
            .is_file()
    );
    fixture.assert_sources();
}

#[tokio::test]
#[ignore = "manual non-test receiver directory-stream rejection"]
async fn production_receiver_rejects_unexpected_downloads_stream() {
    let fixture = Fixture::new();
    let mut stream = fixture.profile.join("Downloads").into_os_string();
    stream.push(":unexpected");
    std::fs::write(PathBuf::from(stream), b"hidden").unwrap();
    let mut child = fixture.start();
    let (status, _stdout, stderr) = fixture.wait(&mut child).await;
    assert!(!status.success());
    assert!(stderr.contains("stream"), "unexpected failure: {stderr}");
    assert!(
        !fixture
            .profile
            .join("Downloads/storytelling-recovery")
            .exists()
    );
    fixture.assert_sources();
}
