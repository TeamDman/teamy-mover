use arbitrary::Arbitrary;
use facet::Facet;
use figue as args;

/// Validate receiver inputs; live receiving remains gated.
#[derive(Facet, Arbitrary, Debug, PartialEq)]
#[facet(rename_all = "kebab-case")]
pub struct TransferReceiveArgs {
    /// Configure and read back an empty Windows job; never launch a receiver.
    #[facet(args::named, default)]
    pub check_process_limit: bool,
    /// Absolute path to local receiver configuration.
    #[facet(args::named)]
    pub config_file: Option<String>,
    /// Validate the local receiver inputs without creating files or listening.
    #[facet(args::named, default)]
    pub validate_only: bool,
}

#[cfg(windows)]
#[derive(Facet)]
#[facet(deny_unknown_fields)]
struct ReceiveConfig {
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

#[cfg(windows)]
#[derive(Debug, Facet)]
struct ValidationSummary {
    valid: bool,
    file_count: u64,
    aggregate_bytes: u64,
    receiver_started: bool,
}

#[cfg(windows)]
#[derive(Facet)]
struct ProcessLimitSummary {
    process_memory_bytes: usize,
    job_configuration_verified: bool,
    process_assigned: bool,
    receiver_started: bool,
}

impl TransferReceiveArgs {
    /// This check runs before runtime startup and grants no transfer capability.
    pub(crate) fn invoke_early(&self) -> eyre::Result<Option<crate::cli::output::CliOutput>> {
        if !self.check_process_limit {
            return Ok(None);
        }
        eyre::ensure!(
            self.config_file.is_none() && !self.validate_only,
            "process-limit check cannot be combined with receiver inputs"
        );
        #[cfg(windows)]
        {
            use crate::transfer::windows_process_limit::PROCESS_MEMORY_BYTES;
            use crate::transfer::windows_process_limit::UnassignedReceiverJob;
            let job = UnassignedReceiverJob::create()?;
            drop(job);
            Ok(Some(crate::cli::output::CliOutput::facet(
                ProcessLimitSummary {
                    process_memory_bytes: PROCESS_MEMORY_BYTES,
                    job_configuration_verified: true,
                    process_assigned: false,
                    receiver_started: false,
                },
                None,
            )))
        }
        #[cfg(not(windows))]
        {
            Err(eyre::eyre!("receiver job-limit check requires Windows"))
        }
    }

    /// Validate locally approved receiver inputs before any listener or stage.
    /// Live receiving remains gated until a qualification can be constructed.
    ///
    /// # Errors
    /// Returns an error for unsafe inputs or an unavailable live qualification.
    pub fn invoke(self) -> eyre::Result<crate::cli::output::CliOutput> {
        if self.config_file.is_none() && !self.validate_only {
            eyre::bail!("transfer is not yet available");
        }
        #[cfg(windows)]
        {
            let summary = validate_config(
                self.config_file
                    .as_deref()
                    .ok_or_else(|| eyre::eyre!("receiver configuration required"))?,
            )?;
            eyre::ensure!(
                self.validate_only,
                "receiver publication qualification is unavailable"
            );
            Ok(crate::cli::output::CliOutput::facet(
                summary,
                Some(std::time::Duration::from_secs(3)),
            ))
        }
        #[cfg(not(windows))]
        {
            eyre::bail!("receiver configuration requires Windows");
        }
    }
}

#[cfg(windows)]
fn validate_config(path: &str) -> eyre::Result<ValidationSummary> {
    use crate::transfer::manifest::{MAX_MANIFEST_BYTES, parse_approved_manifest, valid_component};
    use crate::transfer::proxy::LocalDirectTarget;
    use crate::transfer::tls::ServerEndpoint;
    use eyre::ensure;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use sha2::{Digest, Sha256};
    use std::io::Read;
    use std::os::windows::fs::OpenOptionsExt;
    use std::path::{Component, Path};
    use std::time::{SystemTime, UNIX_EPOCH};
    use windows::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

    fn absolute(path: &str) -> eyre::Result<&Path> {
        let path = Path::new(path);
        ensure!(
            path.is_absolute()
                && path.components().all(|part| matches!(
                    part,
                    Component::Prefix(_) | Component::RootDir | Component::Normal(_)
                )),
            "path must be absolute without traversal"
        );
        Ok(path)
    }
    fn read_file(path: &str, private: bool) -> eyre::Result<Vec<u8>> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(absolute(path)?)?;
        crate::transfer::windows_lock::regular_file_identity(&file)?;
        if private {
            crate::transfer::windows_acl::verify_private_file_acl(&file)?;
        }
        let mut bytes = Vec::new();
        file.take(u64::try_from(MAX_MANIFEST_BYTES)? + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_MANIFEST_BYTES,
            "invalid input file size"
        );
        Ok(bytes)
    }
    fn pin(text: &str) -> eyre::Result<[u8; 32]> {
        ensure!(
            text.len() == 64
                && text
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid certificate pin"
        );
        let mut out = [0; 32];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)?;
        }
        Ok(out)
    }

    let config_bytes = read_file(path, false)?;
    let config: ReceiveConfig = facet_json::from_slice(&config_bytes)
        .map_err(|_error| eyre::eyre!("invalid receiver configuration"))?;
    ensure!(config.version == 1, "unsupported receiver configuration");
    absolute(&config.work_parent)?;
    absolute(&config.destination_parent)?;
    ensure!(
        valid_component(&config.final_name),
        "invalid final directory name"
    );
    let manifest_bytes = read_file(&config.manifest_file, false)?;
    let manifest = parse_approved_manifest(
        &manifest_bytes,
        &config.manifest_sha256,
        &config.transaction_id,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?;
    let server_pin = pin(&config.server_sha256)?;
    let client_pin = pin(&config.client_sha256)?;
    let server = CertificateDer::from(read_file(&config.server_certificate_der, false)?);
    let client = CertificateDer::from(read_file(&config.client_certificate_der, false)?);
    ensure!(
        Sha256::digest(client.as_ref())[..] == client_pin[..],
        "client certificate pin mismatch"
    );
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(read_file(
        &config.server_key_der,
        true,
    )?));
    let endpoint = ServerEndpoint::new(vec![client], vec![server], key, client_pin)?;
    let target = LocalDirectTarget::new(config.target.parse()?, server_pin, client_pin)?;
    target.check_server(target.bind_address(), &endpoint)?;
    Ok(ValidationSummary {
        valid: true,
        file_count: u64::try_from(manifest.files().len())?,
        aggregate_bytes: manifest.aggregate_bytes(),
        receiver_started: false,
    })
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::transfer::windows_acl::{create_private_file, create_synthetic_private_directory};
    use crate::transfer::windows_lock::directory_identity;
    use rcgen::{CertificateParams, KeyPair};
    use sha2::{Digest, Sha256};
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn validates_receiver_inputs_without_creating_a_listener_or_stage() {
        let fixture = tempfile::tempdir().unwrap();
        let keys = create_synthetic_private_directory(&fixture.path().join("keys")).unwrap();
        let key_id = directory_identity(&keys).unwrap();
        let server_key = KeyPair::generate().unwrap();
        let server_cert = CertificateParams::new(vec!["100.64.0.1".to_owned()])
            .unwrap()
            .self_signed(&server_key)
            .unwrap();
        let client_key = KeyPair::generate().unwrap();
        let client_cert = CertificateParams::new(vec!["client".to_owned()])
            .unwrap()
            .self_signed(&client_key)
            .unwrap();
        let mut key = create_private_file(&keys, key_id, "server.pk8").unwrap();
        key.file_mut()
            .write_all(&server_key.serialize_der())
            .unwrap();
        key.file_mut().sync_all().unwrap();
        drop(key);
        let server_path = fixture.path().join("server.der");
        let client_path = fixture.path().join("client.der");
        std::fs::write(&server_path, server_cert.der().as_ref()).unwrap();
        std::fs::write(&client_path, client_cert.der().as_ref()).unwrap();
        let expiry = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;
        let transaction = "0123456789abcdef0123456789abcdef";
        let hash = format!("{:x}", Sha256::digest(b"one"));
        let manifest = format!(
            r#"{{"aggregate_bytes":3,"expires_unix":{expiry},"file_count":1,"files":[{{"id":"one","name":"one.bin","sha256":"{hash}","size":3}}],"transaction_id":"{transaction}","version":1}}"#
        );
        let manifest_path = fixture.path().join("manifest.json");
        std::fs::write(&manifest_path, manifest.as_bytes()).unwrap();
        let config = ReceiveConfig {
            version: 1,
            manifest_file: manifest_path.to_string_lossy().into_owned(),
            manifest_sha256: format!("{:x}", Sha256::digest(manifest.as_bytes())),
            transaction_id: transaction.to_owned(),
            server_certificate_der: server_path.to_string_lossy().into_owned(),
            server_key_der: fixture
                .path()
                .join("keys/server.pk8")
                .to_string_lossy()
                .into_owned(),
            client_certificate_der: client_path.to_string_lossy().into_owned(),
            server_sha256: format!("{:x}", Sha256::digest(server_cert.der().as_ref())),
            client_sha256: format!("{:x}", Sha256::digest(client_cert.der().as_ref())),
            target: "100.64.0.1:49152".to_owned(),
            work_parent: fixture.path().to_string_lossy().into_owned(),
            destination_parent: fixture.path().to_string_lossy().into_owned(),
            final_name: "storytelling-recovery".to_owned(),
        };
        let config_path = fixture.path().join("receive.json");
        std::fs::write(&config_path, facet_json::to_string(&config).unwrap()).unwrap();
        let summary = validate_config(config_path.to_str().unwrap()).unwrap();
        assert!(summary.valid);
        assert_eq!(summary.file_count, 1);
        assert_eq!(summary.aggregate_bytes, 3);
        assert!(!summary.receiver_started);
        assert!(!fixture.path().join("storytelling-recovery").exists());
        let args = TransferReceiveArgs {
            check_process_limit: false,
            config_file: Some(config_path.to_string_lossy().into_owned()),
            validate_only: true,
        };
        let _validated = args.invoke().unwrap();
        let live_args = TransferReceiveArgs {
            check_process_limit: false,
            config_file: Some(config_path.to_string_lossy().into_owned()),
            validate_only: false,
        };
        let Err(gated) = live_args.invoke() else {
            panic!("live receiver must remain gated");
        };
        assert!(gated.to_string().contains("qualification is unavailable"));
        assert!(!fixture.path().join("storytelling-recovery").exists());
        let bad_config = ReceiveConfig {
            client_sha256: "0".repeat(64),
            ..config
        };
        std::fs::write(&config_path, facet_json::to_string(&bad_config).unwrap()).unwrap();
        let _rejected = validate_config(config_path.to_str().unwrap()).unwrap_err();
        assert_eq!(std::fs::read(&manifest_path).unwrap(), manifest.as_bytes());
        assert!(!fixture.path().join("storytelling-recovery").exists());
    }
}
