//! Bounded Vox connection setup for already authenticated TLS streams.
//!
//! This does not establish whole-process memory, session, filesystem, or disk
//! bounds and is not wired to an operational sender or receiver.

use crate::transfer::tls::AuthenticatedClient;
use crate::transfer::tls::AuthenticatedServer;
use crate::transfer::tls::ClientEndpoint;
use eyre::Result;
use std::fmt;
use std::num::NonZeroUsize;
use std::time::Duration;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::io::ReadHalf;
use tokio::io::WriteHalf;
use vox::ConnectionHandle;
use vox::ConnectionResourceLimits;
use vox::ConnectionSettings;
use vox::FromVoxLane;
use vox::LaneAcceptor;
use vox::Parity;
use vox::transport::tcp::StreamLink;

const MAX_FRAME_BYTES: u32 = 64 * 1024;
const ESTABLISH_TIMEOUT: Duration = Duration::from_secs(10);

/// A connection established with Mover's configured Vox ceilings.
#[derive(Clone)]
pub struct BoundedConnection(ConnectionHandle);

impl fmt::Debug for BoundedConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundedConnection").finish_non_exhaustive()
    }
}

fn limits() -> ConnectionResourceLimits {
    ConnectionResourceLimits {
        max_service_lanes: 1,
        max_peer_lane_opens: 1,
        max_inbound_requests_per_lane: 1,
        max_initial_channel_credit: 1,
        max_peer_channel_credit: 1,
        max_peer_concurrent_requests: 1,
        max_peer_calls_per_lane: 64,
        max_peer_channel_ids_per_lane: 32,
        max_schemas_per_lane: 64,
        max_schema_bytes_per_lane: 512 * 1024,
        max_message_processing_time: Duration::from_secs(30),
    }
}

fn link<S>(stream: S) -> StreamLink<ReadHalf<S>, WriteHalf<S>>
where
    S: AsyncRead + AsyncWrite,
{
    let (reader, writer) = tokio::io::split(stream);
    StreamLink::new(reader, writer)
        .max_receive_frame_bytes(MAX_FRAME_BYTES)
        .receive_queue_capacity(NonZeroUsize::MIN)
}

async fn initiate<S>(stream: S) -> Result<BoundedConnection>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let builder = vox::initiator_on(link(stream))
        .max_concurrent_requests(1)
        .channel_capacity(1)
        .resource_limits(limits());
    Ok(BoundedConnection(
        tokio::time::timeout(ESTABLISH_TIMEOUT, builder.establish_connection()).await??,
    ))
}

async fn accept<S>(stream: S, lanes: impl LaneAcceptor) -> Result<BoundedConnection>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let builder = vox::acceptor_on(link(stream))
        .max_concurrent_requests(1)
        .channel_capacity(1)
        .resource_limits(limits())
        .on_lane(lanes);
    Ok(BoundedConnection(
        tokio::time::timeout(ESTABLISH_TIMEOUT, builder.establish_connection()).await??,
    ))
}

/// Establish bounded Vox over a client stream returned by Mover's TLS checks.
///
/// # Errors
/// Returns an error if establishment fails or exceeds its deadline.
pub async fn establish_client<S>(stream: AuthenticatedClient<S>) -> Result<BoundedConnection>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    initiate(stream).await
}

/// Establish bounded Vox over an approved HTTP CONNECT tunnel and pinned mTLS.
///
/// The stream must already be connected to the locally approved proxy, and the
/// target and TLS endpoint must come from the same local transaction approval.
/// This function opens no socket and does not authorize a transfer, publication,
/// or a fallback route. A CONNECT denial is returned before any TLS handshake.
///
/// # Errors
/// Returns an error if CONNECT, TLS authentication or bounded Vox establishment
/// fails or reaches its deadline.
pub async fn establish_client_via_proxy<S>(
    proxy_stream: S,
    target: &str,
    tls: &ClientEndpoint,
) -> Result<BoundedConnection>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let tunnel = crate::transfer::proxy::connect(proxy_stream, target).await?;
    let authenticated = tls.connect(tunnel).await?;
    establish_client(authenticated).await
}

/// Establish bounded Vox over a server stream returned by Mover's TLS checks.
///
/// # Errors
/// Returns an error if establishment fails or exceeds its deadline.
pub async fn establish_server<S>(
    stream: AuthenticatedServer<S>,
    lanes: impl LaneAcceptor,
) -> Result<BoundedConnection>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    accept(stream, lanes).await
}

impl BoundedConnection {
    /// Wait until Vox reports that this connection's control lane is closed.
    /// This signal is asynchronous and does not prove that an otherwise open
    /// peer remains reachable, nor does it by itself authorize a receipt.
    pub async fn closed(&self) {
        self.0.closed().await;
    }

    /// Open a typed lane using explicit limits instead of Vox's wider defaults.
    ///
    /// # Errors
    /// Returns an error when the lane is rejected or its deadline expires.
    pub async fn open_lane<C: FromVoxLane>(&self) -> Result<C> {
        let settings = ConnectionSettings {
            parity: Parity::Odd,
            max_concurrent_requests: 1,
            initial_channel_credit: 1,
        };
        Ok(
            tokio::time::timeout(ESTABLISH_TIMEOUT, self.0.open_lane_with_settings(settings))
                .await??,
        )
    }

    /// Request closure of the bounded connection.
    ///
    /// # Errors
    /// Returns an error if the connection cannot be shut down.
    pub fn shutdown(self) -> Result<()> {
        self.0.shutdown()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use vox::Link;
    use vox::LinkRx;

    #[vox::service]
    trait Echo {
        async fn echo(&self, value: String) -> String;
    }

    #[derive(Clone)]
    struct EchoService;

    impl Echo for EchoService {
        fn echo(&self, value: String) -> impl std::future::Future<Output = String> + Send {
            std::future::ready(value)
        }
    }

    #[tokio::test]
    async fn bounded_connection_accepts_one_lane_and_rejects_a_second_local_open() {
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let (client, server) = tokio::join!(
            initiate(client_io),
            accept(server_io, EchoDispatcher::new(EchoService))
        );
        let client = client.unwrap();
        let _server = server.unwrap();
        let first: EchoClient = client.open_lane().await.unwrap();
        assert_eq!(first.echo("synthetic".into()).await.unwrap(), "synthetic");
        let second = client.open_lane::<EchoClient>().await;
        assert!(second.is_err(), "a second peer lane should be rejected");
    }

    #[tokio::test]
    async fn peer_shutdown_resolves_connection_closed_signal() {
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let (client, server) = tokio::join!(
            initiate(client_io),
            accept(server_io, EchoDispatcher::new(EchoService))
        );
        let client = client.unwrap();
        let server = server.unwrap();
        client.shutdown().unwrap();
        tokio::time::timeout(Duration::from_secs(2), server.closed())
            .await
            .expect("server did not observe peer closure");
    }

    #[tokio::test]
    #[ignore = "diagnostic: peer shutdown with a retained service lane is under investigation"]
    async fn peer_shutdown_is_observed_while_service_lane_is_retained() {
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let (client, server) = tokio::join!(
            initiate(client_io),
            accept(server_io, EchoDispatcher::new(EchoService))
        );
        let client = client.unwrap();
        let server = server.unwrap();
        let lane: EchoClient = client.open_lane().await.unwrap();
        client.shutdown().unwrap();
        if tokio::time::timeout(Duration::from_secs(2), server.closed())
            .await
            .is_err()
        {
            drop(lane);
            tokio::time::timeout(Duration::from_secs(2), server.closed())
                .await
                .expect("server did not observe shutdown after service lane was dropped");
            panic!("server only observed shutdown after the service lane was dropped");
        }
    }

    #[tokio::test]
    async fn abrupt_transport_loss_closes_both_peers_with_service_lane_retained() {
        let (client_io, mut bridge_left) = tokio::io::duplex(128 * 1024);
        let (server_io, mut bridge_right) = tokio::io::duplex(128 * 1024);
        let bridge = tokio::spawn(async move {
            let _result = tokio::io::copy_bidirectional(&mut bridge_left, &mut bridge_right).await;
        });
        let (client, server) = tokio::join!(
            initiate(client_io),
            accept(server_io, EchoDispatcher::new(EchoService))
        );
        let client = client.unwrap();
        let server = server.unwrap();
        let lane: EchoClient = client.open_lane().await.unwrap();
        assert_eq!(
            lane.echo("before loss".into()).await.unwrap(),
            "before loss"
        );
        bridge.abort();
        let _stopped = bridge.await.unwrap_err();
        tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(client.closed(), server.closed());
        })
        .await
        .expect("both peers must observe abrupt transport loss");
        let _closed = lane.echo("after loss".into()).await.unwrap_err();
    }

    #[tokio::test]
    async fn receiver_rejects_peer_lane_with_excessive_limits() {
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let (client, server) = tokio::join!(
            vox::initiator_on(link(client_io))
                .max_concurrent_requests(1)
                .channel_capacity(1)
                .establish_connection(),
            accept(server_io, EchoDispatcher::new(EchoService))
        );
        let client = client.unwrap();
        let _server = server.unwrap();
        let settings = ConnectionSettings {
            parity: Parity::Odd,
            max_concurrent_requests: 64,
            initial_channel_credit: 16,
        };
        let result = client.open_lane_with_settings::<EchoClient>(settings).await;
        assert!(
            matches!(result, Err(vox::ConnectionError::Rejected(ref rejection)) if rejection.reason() == vox::LaneRejectReason::PolicyRejected),
            "receiver must reject peer-supplied excessive limits"
        );
    }

    #[tokio::test]
    async fn receiver_rejects_an_unbounded_peers_second_lane() {
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let (client, server) = tokio::join!(
            vox::initiator_on(link(client_io))
                .max_concurrent_requests(1)
                .channel_capacity(1)
                .establish_connection(),
            accept(server_io, EchoDispatcher::new(EchoService))
        );
        let client = client.unwrap();
        let _server = server.unwrap();
        let settings = ConnectionSettings {
            parity: Parity::Odd,
            max_concurrent_requests: 1,
            initial_channel_credit: 1,
        };
        let _first: EchoClient = client
            .open_lane_with_settings(settings.clone())
            .await
            .unwrap();
        let result = client.open_lane_with_settings::<EchoClient>(settings).await;
        assert!(
            matches!(result, Err(vox::ConnectionError::Rejected(ref rejection)) if rejection.reason() == vox::LaneRejectReason::NotReady),
            "receiver must reject the peer's second lane"
        );
    }

    #[tokio::test]
    async fn stream_rejects_oversized_frame_before_body_arrives() {
        let (mut peer, receiver) = tokio::io::duplex(1024);
        let (_writer, mut reader) = link(receiver).split();
        let mut prefix = b"VOXL\x01\x00".to_vec();
        prefix.extend_from_slice(&(MAX_FRAME_BYTES + 1).to_le_bytes());
        peer.write_all(&prefix).await.unwrap();
        let error = tokio::time::timeout(Duration::from_secs(2), reader.recv())
            .await
            .unwrap()
            .err()
            .expect("oversized frame must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}
