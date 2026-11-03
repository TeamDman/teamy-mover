//! Bounded HTTP CONNECT negotiation over an already connected proxy stream.
//!
//! This only constructs a tunnel. Callers must select the locally approved
//! proxy and target and complete authenticated TLS before sending Vox data.

use bytes::Bytes;
use eyre::Result;
use eyre::bail;
use eyre::ensure;
use http_body_util::Empty;
use hyper::Method;
use hyper::Request;
use hyper::StatusCode;
use hyper::Uri;
use hyper::client::conn::http1;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::time::Duration;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::task::JoinHandle;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PROXY_RESPONSE_BYTES: usize = 8192;
const MAX_PROXY_HEADERS: usize = 32;

/// Exact IP/port and peer certificate pins supplied by local configuration.
/// Constructing this value does not itself establish the configuration's trust,
/// authorize a transfer, or prove that a Tailscale peer owns the IP address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalDirectTarget {
    endpoint: SocketAddrV4,
    server_pin: [u8; 32],
    client_pin: [u8; 32],
}

impl LocalDirectTarget {
    /// Validate the shape of a locally approved direct target. The caller must
    /// independently establish the authority and integrity of these inputs.
    ///
    /// # Errors
    /// Rejects an address outside 100.64.0.0/10 or an unspecified port.
    pub fn new(endpoint: SocketAddrV4, server_pin: [u8; 32], client_pin: [u8; 32]) -> Result<Self> {
        let octets = endpoint.ip().octets();
        ensure!(
            octets[0] == 100 && (octets[1] & 0xc0) == 0x40 && endpoint.port() != 0,
            "direct target must have a nonzero port and an IPv4 address in 100.64.0.0/10"
        );
        Ok(Self {
            endpoint,
            server_pin,
            client_pin,
        })
    }

    /// Confirm the configured TLS name and both certificate pins match this
    /// target before performing CONNECT. This does not perform a handshake.
    ///
    /// # Errors
    /// Rejects an endpoint with a different IP identity or certificate pin.
    pub fn check_tls(&self, tls: &super::tls::ClientEndpoint) -> Result<()> {
        ensure!(
            tls.matches_ip_and_pins(*self.endpoint.ip(), &self.server_pin, &self.client_pin),
            "TLS identity does not match local target"
        );
        Ok(())
    }

    /// Check the requested or observed listener address and server certificate
    /// configuration against this local target. Call before bind and again on
    /// the bound socket; neither check creates a listener or authorizes it.
    ///
    /// # Errors
    /// Rejects a different address, port, server certificate, or client pin.
    pub fn check_server(
        &self,
        address: SocketAddr,
        tls: &super::tls::ServerEndpoint,
    ) -> Result<()> {
        ensure!(
            address == SocketAddr::V4(self.endpoint)
                && tls.matches_pins(&self.server_pin, &self.client_pin),
            "receiver address or TLS identity does not match local target"
        );
        Ok(())
    }

    /// The exact locally configured address a future qualified receiver must
    /// validate before and after binding. Returning it opens no socket.
    #[must_use]
    pub const fn bind_address(&self) -> SocketAddr {
        SocketAddr::V4(self.endpoint)
    }

    /// Exact authority to use for the approved CONNECT request.
    #[must_use]
    pub fn authority(&self) -> String {
        self.endpoint.to_string()
    }
}

struct AbortDriver(JoinHandle<()>);

impl Drop for AbortDriver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Request a CONNECT tunnel to a locally approved host and explicit port.
///
/// `stream` must already be connected to the locally approved proxy; `target`
/// must come from protected local configuration, never an untrusted request.
/// The returned stream preserves bytes buffered by Hyper during the upgrade.
/// It is not authenticated or encrypted until the caller establishes TLS.
///
/// # Errors
/// Returns an error for invalid targets, protocol errors, non-200 responses,
/// excessive response headers, or a timeout. No fallback route is attempted.
pub async fn connect<S>(stream: S, target: &str) -> Result<TokioIo<Upgraded>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    connect_with_timeout(stream, target, CONNECT_TIMEOUT).await
}

async fn connect_with_timeout<S>(
    stream: S,
    target: &str,
    timeout: Duration,
) -> Result<TokioIo<Upgraded>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let uri: Uri = target.parse()?;
    let authority = uri
        .authority()
        .ok_or_else(|| eyre::eyre!("CONNECT target must be an authority"))?;
    ensure!(
        uri.scheme().is_none(),
        "CONNECT target must not contain a scheme"
    );
    ensure!(
        uri.path().is_empty(),
        "CONNECT target must not contain a path"
    );
    ensure!(
        uri.query().is_none(),
        "CONNECT target must not contain a query"
    );
    ensure!(
        !authority.as_str().contains('@'),
        "CONNECT target must not contain user info"
    );
    ensure!(
        authority.port_u16().is_some_and(|port| port != 0),
        "CONNECT target requires a nonzero port"
    );

    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(uri.clone())
        .header(hyper::header::HOST, authority.as_str())
        .body(Empty::<Bytes>::new())?;

    let task = async move {
        let mut builder = http1::Builder::new();
        builder.max_buf_size(MAX_PROXY_RESPONSE_BYTES);
        builder.max_headers(MAX_PROXY_HEADERS);
        let (mut sender, connection) = builder.handshake(TokioIo::new(stream)).await?;
        let mut driver = AbortDriver(tokio::spawn(async move {
            let _result = connection.with_upgrades().await;
        }));
        let response = sender.send_request(request).await?;
        if response.status() != StatusCode::OK {
            bail!("CONNECT proxy returned HTTP {}", response.status().as_u16());
        }
        let upgraded = hyper::upgrade::on(response).await?;
        (&mut driver.0).await?;
        Ok(TokioIo::new(upgraded))
    };
    with_timeout(timeout, task).await
}

async fn with_timeout<T>(duration: Duration, task: impl Future<Output = Result<T>>) -> Result<T> {
    tokio::time::timeout(duration, task)
        .await
        .map_err(|error| eyre::eyre!("CONNECT proxy timed out: {error}"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    fn proxy_response(response: Vec<u8>) -> tokio::io::DuplexStream {
        let (client, mut proxy) = tokio::io::duplex(16 * 1024);
        tokio::spawn(async move {
            let mut request = Vec::new();
            loop {
                let byte = proxy.read_u8().await.unwrap();
                request.push(byte);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
                assert!(request.len() < 2048);
            }
            assert!(request.starts_with(b"CONNECT 100.64.0.1:49152 HTTP/1.1\r\n"));
            proxy.write_all(&response).await.unwrap();
        });
        client
    }

    #[tokio::test]
    async fn successful_upgrade_preserves_buffered_tunnel_bytes() {
        let mut reply = b"HTTP/1.1 200 Connection Established\r\n\r\n".to_vec();
        reply.extend_from_slice(&[0x16, 0x03, 0x01]);
        let stream = proxy_response(reply);
        let mut tunnel = connect(stream, "100.64.0.1:49152").await.unwrap();
        let mut got = [0_u8; 3];
        tunnel.read_exact(&mut got).await.unwrap();
        assert_eq!(got, [0x16, 0x03, 0x01]);
    }

    #[tokio::test]
    async fn rejects_proxy_denial_redirect_and_oversized_headers() {
        for status in [
            "503 Service Unavailable",
            "302 Found",
            "407 Proxy Authentication Required",
        ] {
            let reply = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n");
            let stream = proxy_response(reply.into_bytes());
            let _error = connect(stream, "100.64.0.1:49152").await.unwrap_err();
        }
        let reply = format!(
            "HTTP/1.1 200 OK\r\nX-Oversized: {}\r\n\r\n",
            "x".repeat(9000)
        );
        let stream = proxy_response(reply.into_bytes());
        let _error = connect(stream, "100.64.0.1:49152").await.unwrap_err();
    }

    #[tokio::test]
    async fn rejects_unapproved_target_shapes_and_times_out() {
        for target in [
            "https://example.test:443",
            "example.test",
            "user@example.test:80",
            "example.test:0",
            "example.test:80/path",
            "example.test:80?query",
        ] {
            let (stream, _peer) = tokio::io::duplex(1024);
            assert!(connect(stream, target).await.is_err(), "accepted {target}");
        }
        let (stream, _peer) = tokio::io::duplex(1024);
        let result =
            connect_with_timeout(stream, "100.64.0.1:49152", Duration::from_millis(25)).await;
        let _error = result.unwrap_err();
    }
}
