//! TCP port forwarding between trusted peers.
//!
//! One side serves a local TCP address (`NodeBuilder::serve_tcp`); the other listens on a
//! loopback port (`Node::forward_tcp`) and every connection made to it becomes a QUIC
//! stream to the serving peer, which opens a TCP connection to its target and pipes
//! bytes both ways. The app on the forwarding side just talks TCP to `127.0.0.1:<port>`,
//! so existing HTTP/TLS clients work unchanged, over whatever path tethersys finds
//! (LAN, hole-punched, or relayed). Both ends sit behind the trust gate: only paired
//! peers can open a forward, and removing a peer stops new ones.

use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use iroh::{
    endpoint::{Connection, RecvStream, SendStream},
    protocol::{AcceptError, ProtocolHandler},
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

use crate::{identity::NodeId, node::Node, trust::TrustStore};

/// The protocol a forwarded stream travels on.
pub const FORWARD_ALPN: &[u8] = b"tethersys/forward/1";

/// Serves forwarded TCP: every stream a trusted peer opens is piped to `target`.
#[derive(Debug, Clone)]
pub(crate) struct ForwardServer {
    target: SocketAddr,
    trust: Arc<TrustStore>,
}

impl ForwardServer {
    pub(crate) fn new(target: SocketAddr, trust: Arc<TrustStore>) -> Self {
        Self { target, trust }
    }
}

impl ProtocolHandler for ForwardServer {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let peer = conn.remote_id();
        while let Ok((send, recv)) = conn.accept_bi().await {
            // The gate only runs at the handshake; a peer removed since then is cut off here.
            if !self.trust.is_allowed(&peer) {
                conn.close(1u32.into(), b"not trusted");
                break;
            }
            let target = self.target;
            tokio::spawn(async move {
                match TcpStream::connect(target).await {
                    Ok(tcp) => pipe(tcp, send, recv).await,
                    Err(e) => tracing::debug!(%target, "forward target refused: {e}"),
                }
            });
        }
        Ok(())
    }
}

/// Copies both ways until each side has finished, then closes the other.
async fn pipe(tcp: TcpStream, mut send: SendStream, mut recv: RecvStream) {
    let _ = tcp.set_nodelay(true);
    let (mut r, mut w) = tcp.into_split();
    let up = async {
        let _ = tokio::io::copy(&mut r, &mut send).await;
        let _ = send.finish();
    };
    let down = async {
        let _ = tokio::io::copy(&mut recv, &mut w).await;
        let _ = w.shutdown().await;
    };
    tokio::join!(up, down);
}

/// A running forward. Dropping it closes the local port; streams already open finish.
#[derive(Debug)]
pub struct Forward {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl Forward {
    /// The loopback address the app connects to.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for Forward {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Node {
    /// Listen on `local` (use `127.0.0.1:0` for any free port) and forward every TCP
    /// connection made to it to `peer`, which must serve TCP (`NodeBuilder::serve_tcp`).
    /// The connection to the peer is opened on the first use and reused after that.
    pub async fn forward_tcp(&self, peer: NodeId, local: SocketAddr) -> Result<Forward> {
        let listener = TcpListener::bind(local)
            .await
            .with_context(|| format!("listen on {local}"))?;
        let addr = listener.local_addr()?;
        let node = self.clone();
        let task = tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let node = node.clone();
                tokio::spawn(async move {
                    match node.open_forward_stream(peer).await {
                        Ok((send, recv)) => pipe(tcp, send, recv).await,
                        Err(e) => {
                            tracing::debug!(peer = %peer.fmt_short(), "forward failed: {e:#}")
                        }
                    }
                });
            }
        });
        Ok(Forward { addr, task })
    }

    /// A stream to the peer's forward server, on a fresh connection if the pooled one died.
    async fn open_forward_stream(&self, peer: NodeId) -> Result<(SendStream, RecvStream)> {
        let conn = self.connect(peer, FORWARD_ALPN).await?;
        match conn.open_bi().await {
            Ok(s) => Ok(s),
            Err(_) => {
                self.inner().forget(peer, FORWARD_ALPN);
                let conn = self.connect(peer, FORWARD_ALPN).await?;
                Ok(conn.open_bi().await.context("open stream")?)
            }
        }
    }
}
