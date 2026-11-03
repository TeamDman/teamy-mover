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
use teamy_mover::transfer::tls::ClientEndpoint;
use teamy_mover::transfer::tls::ServerEndpoint;
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
