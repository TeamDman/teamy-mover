//! Mutual TLS with normal `WebPKI` validation and locally approved leaf pins.
//!
//! TLS streams are returned only after the handshake and leaf-pin checks.
//! These helpers do not open sockets or authorize a transfer transaction.

use eyre::Result;
use eyre::ensure;
use rustls::ClientConfig;
use rustls::RootCertStore;
use rustls::ServerConfig;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::ServerName;
use rustls::server::WebPkiClientVerifier;
use sha2::Digest;
use sha2::Sha256;
use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::io::ReadBuf;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::TlsConnector;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// TLS client configuration bound to a server identity and certificate pin.
#[derive(Clone)]
pub struct ClientEndpoint {
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    server_pin: [u8; 32],
}

/// TLS server configuration bound to an approved client certificate pin.
#[derive(Clone)]
pub struct ServerEndpoint {
    config: Arc<ServerConfig>,
    client_pin: [u8; 32],
}

/// Client stream returned only after ordinary TLS validation and pin checking.
pub struct AuthenticatedClient<S>(tokio_rustls::client::TlsStream<S>);

/// Server stream returned only after ordinary mutual-TLS validation and pin checking.
pub struct AuthenticatedServer<S>(tokio_rustls::server::TlsStream<S>);

macro_rules! authenticated_stream {
    ($name:ident) => {
        impl<S> fmt::Debug for $name<S> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }

        impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for $name<S> {
            fn poll_read(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
            }
        }

        impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for $name<S> {
            fn poll_write(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
            }

            fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.get_mut().0).poll_flush(cx)
            }

            fn poll_shutdown(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
            }
        }
    };
}

authenticated_stream!(AuthenticatedClient);
authenticated_stream!(AuthenticatedServer);

impl fmt::Debug for ClientEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientEndpoint").finish_non_exhaustive()
    }
}

impl fmt::Debug for ServerEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerEndpoint").finish_non_exhaustive()
    }
}

fn roots(certificates: Vec<CertificateDer<'static>>) -> Result<RootCertStore> {
    ensure!(!certificates.is_empty(), "empty TLS trust store");
    let mut store = RootCertStore::empty();
    for certificate in certificates {
        store.add(certificate)?;
    }
    Ok(store)
}

fn verify_leaf(certificates: Option<&[CertificateDer<'_>]>, expected: &[u8; 32]) -> Result<()> {
    let leaf = certificates
        .and_then(|certificates| certificates.first())
        .ok_or_else(|| eyre::eyre!("TLS peer did not present a certificate"))?;
    let actual = Sha256::digest(leaf.as_ref());
    ensure!(
        actual[..] == expected[..],
        "TLS peer certificate pin mismatch"
    );
    Ok(())
}

impl ClientEndpoint {
    /// Construct a client using only locally configured trust and identity.
    /// The server name must be the approved DNS name or IP address.
    ///
    /// # Errors
    /// Returns an error for invalid trust roots, identity or TLS configuration.
    pub fn new(
        trust_roots: Vec<CertificateDer<'static>>,
        client_chain: Vec<CertificateDer<'static>>,
        client_key: PrivateKeyDer<'static>,
        server_name: ServerName<'static>,
        server_pin: [u8; 32],
    ) -> Result<Self> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots(trust_roots)?)
            .with_client_auth_cert(client_chain, client_key)?;
        config.enable_early_data = false;
        config.resumption = rustls::client::Resumption::disabled();
        Ok(Self {
            config: Arc::new(config),
            server_name,
            server_pin,
        })
    }

    /// Perform the bounded handshake and return only a pinned TLS stream.
    ///
    /// # Errors
    /// Returns an error on timeout, TLS validation failure, or a pin mismatch.
    pub async fn connect<S>(&self, stream: S) -> Result<AuthenticatedClient<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let connector = TlsConnector::from(Arc::clone(&self.config));
        let tls = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            connector.connect(self.server_name.clone(), stream),
        )
        .await??;
        verify_leaf(tls.get_ref().1.peer_certificates(), &self.server_pin)?;
        Ok(AuthenticatedClient(tls))
    }
}

impl ServerEndpoint {
    /// Construct a server requiring a normally verified client certificate.
    ///
    /// # Errors
    /// Returns an error for invalid trust roots, identity or TLS configuration.
    pub fn new(
        trust_roots: Vec<CertificateDer<'static>>,
        server_chain: Vec<CertificateDer<'static>>,
        server_key: PrivateKeyDer<'static>,
        client_pin: [u8; 32],
    ) -> Result<Self> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots(trust_roots)?),
            Arc::clone(&provider),
        )
        .build()?;
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_client_cert_verifier(verifier)
            .with_single_cert(server_chain, server_key)?;
        config.max_early_data_size = 0;
        config.send_tls13_tickets = 0;
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        Ok(Self {
            config: Arc::new(config),
            client_pin,
        })
    }

    /// Perform the bounded handshake and return only a pinned TLS stream.
    ///
    /// # Errors
    /// Returns an error on timeout, TLS validation failure, or a pin mismatch.
    pub async fn accept<S>(&self, stream: S) -> Result<AuthenticatedServer<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let acceptor = TlsAcceptor::from(Arc::clone(&self.config));
        let tls = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await??;
        verify_leaf(tls.get_ref().1.peer_certificates(), &self.client_pin)?;
        Ok(AuthenticatedServer(tls))
    }
}
