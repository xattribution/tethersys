//! Messages and request/response between peers.
//!
//! Every message rides its own QUIC stream on a pooled connection, so a slow message never
//! blocks a fast one. Messages carry a random id; receivers drop duplicates, which makes it
//! safe to retry, and safe for the same message to arrive both live and from the mailbox.

use std::{
    collections::{HashSet, VecDeque},
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};

use anyhow::{Result, bail};
use bytes::Bytes;
use iroh::{
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler},
};
use serde::{Deserialize, Serialize};

use crate::{
    events::{Event, LinkKind},
    identity::NodeId,
    node::Inner,
    wire::{random_bytes, read_frame, write_frame},
};

pub const ALPN: &[u8] = b"tethersys/msg/1";

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;
pub type RequestHandler = Arc<dyn Fn(NodeId, Bytes) -> BoxFuture<Result<Bytes>> + Send + Sync>;

/// How hard `send` should try.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Delivery {
    /// Live delivery only. Fails if the peer cannot be reached right now.
    Direct,
    /// Live delivery, falling back to the server mailbox when the peer is offline.
    #[default]
    Auto,
    /// Skip the live attempt and queue in the mailbox.
    Mailbox,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MsgReq {
    pub id: [u8; 16],
    pub channel: String,
    pub body: Vec<u8>,
    pub want_reply: bool,
}

#[derive(Debug, Serialize, Deserialize)]
enum MsgResp {
    Ack,
    Reply(Vec<u8>),
    Error(String),
}

/// Bounded memory of recent message ids for duplicate suppression.
#[derive(Debug, Default)]
pub(crate) struct Seen(Mutex<SeenSet>);

type SeenSet = (HashSet<[u8; 16]>, VecDeque<[u8; 16]>);

impl Seen {
    const CAP: usize = 8192;
    /// Returns true the first time an id is seen.
    pub fn first(&self, id: [u8; 16]) -> bool {
        let mut g = self.0.lock().unwrap();
        if !g.0.insert(id) {
            return false;
        }
        g.1.push_back(id);
        if g.1.len() > Self::CAP
            && let Some(old) = g.1.pop_front()
        {
            g.0.remove(&old);
        }
        true
    }
}

#[derive(Debug, Clone)]
pub(crate) struct MessagingHandler(pub Arc<Inner>);

impl ProtocolHandler for MessagingHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let peer = conn.remote_id();
        self.0.watch_link(peer, &conn);
        loop {
            let (mut send, mut recv) = match conn.accept_bi().await {
                Ok(s) => s,
                Err(_) => return Ok(()), // connection closed
            };
            let inner = self.0.clone();
            tokio::spawn(async move {
                let resp = match read_frame::<MsgReq>(&mut recv).await {
                    Ok(req) => inner.dispatch(peer, req, false).await,
                    Err(e) => MsgResp::Error(e.to_string()),
                };
                let _ = write_frame(&mut send, &resp).await;
                let _ = send.finish();
                let _ = send.stopped().await;
            });
        }
    }
}

impl Inner {
    async fn dispatch(&self, from: NodeId, req: MsgReq, from_mailbox: bool) -> MsgResp {
        if !self.seen.first(req.id) {
            return MsgResp::Ack;
        }
        let handler = self.handlers.read().unwrap().get(&req.channel).cloned();
        match handler {
            Some(h) => match h(from, Bytes::from(req.body)).await {
                Ok(reply) if req.want_reply => MsgResp::Reply(reply.to_vec()),
                Ok(_) => MsgResp::Ack,
                Err(e) => MsgResp::Error(e.to_string()),
            },
            None if req.want_reply => MsgResp::Error(format!("no handler for '{}'", req.channel)),
            None => {
                self.on_inbound_message(from, req, from_mailbox);
                MsgResp::Ack
            }
        }
    }

    pub(crate) fn on_inbound_message(&self, from: NodeId, req: MsgReq, from_mailbox: bool) {
        #[cfg(feature = "files")]
        if req.channel == crate::files::OFFER_CHANNEL {
            self.on_file_offer(from, &req.body);
            return;
        }
        let _ = self.events.send(Event::Message {
            from,
            channel: req.channel,
            body: Bytes::from(req.body),
            from_mailbox,
        });
    }

    /// Mailbox deliveries go through the same path as live ones, minus the reply.
    #[cfg(feature = "mailbox")]
    pub(crate) async fn dispatch_from_mailbox(&self, from: NodeId, req: MsgReq) {
        let _ = self.dispatch(from, req, true).await;
    }

    pub(crate) async fn send_message(
        &self,
        to: NodeId,
        channel: &str,
        body: Bytes,
        delivery: Delivery,
    ) -> Result<LinkKind> {
        let req = MsgReq {
            id: random_bytes(),
            channel: channel.to_string(),
            body: body.to_vec(),
            want_reply: false,
        };
        if delivery != Delivery::Mailbox {
            match self.live_call(to, &req).await {
                Ok((MsgResp::Error(e), _)) => bail!("peer rejected message: {e}"),
                Ok((_, link)) => return Ok(link),
                Err(e) if delivery == Delivery::Direct => return Err(e),
                Err(e) => {
                    tracing::debug!(peer = %to.fmt_short(), "live send failed, queueing: {e:#}")
                }
            }
        }
        #[cfg(feature = "mailbox")]
        {
            self.mailbox_put(to, &req).await?;
            Ok(LinkKind::Queued)
        }
        #[cfg(not(feature = "mailbox"))]
        bail!(
            "{} is unreachable and the mailbox feature is off",
            to.fmt_short()
        )
    }

    pub(crate) async fn request(&self, to: NodeId, channel: &str, body: Bytes) -> Result<Bytes> {
        let req = MsgReq {
            id: random_bytes(),
            channel: channel.to_string(),
            body: body.to_vec(),
            want_reply: true,
        };
        match self.live_call(to, &req).await?.0 {
            MsgResp::Reply(b) => Ok(Bytes::from(b)),
            MsgResp::Ack => Ok(Bytes::new()),
            MsgResp::Error(e) => bail!("peer error: {e}"),
        }
    }

    async fn live_call(&self, to: NodeId, req: &MsgReq) -> Result<(MsgResp, LinkKind)> {
        // A pooled connection can die silently (phone changed networks). Redial once.
        let mut last_err = None;
        for _ in 0..2 {
            let conn = self.connect(to, ALPN).await?;
            match crate::wire::call(&conn, req).await {
                Ok(resp) => return Ok((resp, crate::node::link_of(&conn))),
                Err(e) => {
                    self.forget(to, ALPN);
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.expect("loop ran"))
    }
}
