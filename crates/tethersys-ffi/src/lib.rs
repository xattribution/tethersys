//! Foreign-language face of tethersys (Kotlin for Android, Swift for iOS, C# for Windows).
//!
//! The surface is deliberately flat: ids are strings, payloads are byte arrays, and every
//! event arrives through one listener callback. Topics and spaces are opened lazily by name.

use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

use tethersys::{
    Config, Event, Forward, LinkKind, Node, NodeId, Profile, ServerTicket, Space, Topic,
};
use tokio::sync::Mutex;

uniffi::setup_scaffolding!();

/// Flat, so Kotlin gets `TethersysException.Failed(message)` with the text as the
/// exception's own message (a `message` field would clash with Throwable.message).
#[derive(Debug, uniffi::Error)]
#[uniffi(flat_error)]
pub enum TethersysError {
    Failed { message: String },
}

impl std::fmt::Display for TethersysError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TethersysError::Failed { message } => f.write_str(message),
        }
    }
}

impl std::error::Error for TethersysError {}

impl From<anyhow::Error> for TethersysError {
    fn from(e: anyhow::Error) -> Self {
        TethersysError::Failed {
            message: format!("{e:#}"),
        }
    }
}

type Result<T> = std::result::Result<T, TethersysError>;

fn fail(message: impl Into<String>) -> TethersysError {
    TethersysError::Failed {
        message: message.into(),
    }
}

fn parse_id(s: &str) -> Result<NodeId> {
    s.parse().map_err(|_| fail(format!("not a node id: {s}")))
}

#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum FfiProfile {
    Public,
    Hybrid,
    SelfHosted,
    Local,
    Sovereign,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiConfig {
    pub name: String,
    pub data_dir: String,
    pub profile: FfiProfile,
    /// Required for Hybrid and SelfHosted.
    pub server_ticket: Option<String>,
    /// Download offered files here automatically.
    pub auto_accept_dir: Option<String>,
    pub hide_ip: bool,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiLink {
    Direct,
    Relayed,
    Queued,
}

impl From<LinkKind> for FfiLink {
    fn from(l: LinkKind) -> Self {
        match l {
            LinkKind::Direct => FfiLink::Direct,
            LinkKind::Relayed => FfiLink::Relayed,
            LinkKind::Queued => FfiLink::Queued,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiPeer {
    pub id: String,
    pub name: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiFileOffer {
    pub from: String,
    pub hash: String,
    pub name: String,
    pub size: u64,
    pub providers: Vec<String>,
}

impl From<tethersys::FileOffer> for FfiFileOffer {
    fn from(o: tethersys::FileOffer) -> Self {
        Self {
            from: o.from.to_string(),
            hash: o.hash,
            name: o.name,
            size: o.size,
            providers: o.providers.iter().map(|p| p.to_string()).collect(),
        }
    }
}

impl TryFrom<FfiFileOffer> for tethersys::FileOffer {
    type Error = TethersysError;
    fn try_from(o: FfiFileOffer) -> Result<Self> {
        Ok(Self {
            from: parse_id(&o.from)?,
            hash: o.hash,
            name: o.name,
            size: o.size,
            providers: o
                .providers
                .iter()
                .map(|p| parse_id(p))
                .collect::<Result<_>>()?,
        })
    }
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum FfiEvent {
    Connected {
        peer: String,
        link: FfiLink,
    },
    LinkChanged {
        peer: String,
        link: FfiLink,
        rtt_ms: u64,
    },
    Paired {
        peer: String,
        name: String,
    },
    Message {
        from: String,
        channel: String,
        body: Vec<u8>,
        from_mailbox: bool,
    },
    FileOffered {
        offer: FfiFileOffer,
    },
    FileProgress {
        hash: String,
        bytes: u64,
        total: u64,
    },
    FileDone {
        hash: String,
        path: String,
    },
    FileFailed {
        hash: String,
        error: String,
    },
    TopicMessage {
        topic: String,
        author: String,
        body: Vec<u8>,
    },
    SpaceChanged {
        space: String,
        key: String,
        author: String,
        deleted: bool,
    },
    Server {
        connected: bool,
        detail: String,
    },
}

impl From<Event> for FfiEvent {
    fn from(e: Event) -> Self {
        match e {
            Event::Connected { peer, link } => FfiEvent::Connected {
                peer: peer.to_string(),
                link: link.into(),
            },
            Event::LinkChanged { peer, link, rtt_ms } => FfiEvent::LinkChanged {
                peer: peer.to_string(),
                link: link.into(),
                rtt_ms,
            },
            Event::Paired { peer, name } => FfiEvent::Paired {
                peer: peer.to_string(),
                name,
            },
            Event::Message {
                from,
                channel,
                body,
                from_mailbox,
            } => FfiEvent::Message {
                from: from.to_string(),
                channel,
                body: body.to_vec(),
                from_mailbox,
            },
            Event::FileOffered(o) => FfiEvent::FileOffered { offer: o.into() },
            Event::FileProgress { hash, bytes, total } => {
                FfiEvent::FileProgress { hash, bytes, total }
            }
            Event::FileDone { hash, path } => FfiEvent::FileDone {
                hash,
                path: path.display().to_string(),
            },
            Event::FileFailed { hash, error } => FfiEvent::FileFailed { hash, error },
            Event::TopicMessage {
                topic,
                author,
                body,
            } => FfiEvent::TopicMessage {
                topic,
                author: author.to_string(),
                body: body.to_vec(),
            },
            Event::SpaceChanged {
                space,
                key,
                author,
                deleted,
            } => FfiEvent::SpaceChanged {
                space,
                key,
                author: author.to_string(),
                deleted,
            },
            Event::Server { connected, detail } => FfiEvent::Server { connected, detail },
        }
    }
}

/// Implemented by the app to receive every event.
#[uniffi::export(with_foreign)]
pub trait EventListener: Send + Sync {
    fn on_event(&self, event: FfiEvent);
}

/// Implemented by the app to answer requests on a channel.
#[uniffi::export(with_foreign)]
pub trait RequestHandler: Send + Sync {
    fn handle(&self, from: String, body: Vec<u8>) -> Vec<u8>;
}

#[derive(uniffi::Object)]
pub struct TethersysNode {
    node: Node,
    topics: Mutex<HashMap<String, Topic>>,
    spaces: Mutex<HashMap<String, Space>>,
    forwards: Mutex<HashMap<NodeId, Forward>>,
}

impl TethersysNode {
    async fn topic(&self, name: &str) -> Result<Topic> {
        let mut t = self.topics.lock().await;
        if let Some(topic) = t.get(name) {
            return Ok(topic.clone());
        }
        let topic = self.node.topic(name).await?;
        t.insert(name.to_string(), topic.clone());
        Ok(topic)
    }

    async fn space(&self, name: &str) -> Result<Space> {
        let mut s = self.spaces.lock().await;
        if let Some(space) = s.get(name) {
            return Ok(space.clone());
        }
        let space = self.node.space(name).await?;
        s.insert(name.to_string(), space.clone());
        Ok(space)
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl TethersysNode {
    #[uniffi::constructor]
    pub async fn start(config: FfiConfig, listener: Arc<dyn EventListener>) -> Result<Arc<Self>> {
        let ticket = config
            .server_ticket
            .as_deref()
            .map(ServerTicket::decode)
            .transpose()?;
        let profile = match (config.profile, ticket) {
            (FfiProfile::Public, _) => Profile::Public,
            (FfiProfile::Local, _) => Profile::Local,
            (FfiProfile::Sovereign, _) => Profile::Sovereign,
            (FfiProfile::Hybrid, Some(t)) => Profile::Hybrid(t),
            (FfiProfile::SelfHosted, Some(t)) => Profile::SelfHosted(t),
            _ => return Err(fail("this profile needs a server_ticket")),
        };
        let mut cfg = Config::new(config.name, profile).data_dir(config.data_dir);
        cfg.auto_accept_files = config.auto_accept_dir.map(PathBuf::from);
        cfg.hide_ip = config.hide_ip;
        cfg.port = config.port;
        let node = Node::spawn(cfg).await?;

        let mut rx = node.events();
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(ev) => listener.on_event(ev.into()),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                }
            }
        });
        Ok(Arc::new(Self {
            node,
            topics: Mutex::new(HashMap::new()),
            spaces: Mutex::new(HashMap::new()),
            forwards: Mutex::new(HashMap::new()),
        }))
    }

    pub fn id(&self) -> String {
        self.node.id().to_string()
    }

    /// Invite string for a QR code or link.
    pub fn invite(&self, ttl_secs: u64, uses: u32) -> String {
        self.node
            .invite(Duration::from_secs(ttl_secs), uses)
            .encode()
    }

    pub async fn join(&self, invite: String) -> Result<FfiPeer> {
        let p = self.node.join(&invite).await?;
        Ok(FfiPeer {
            id: p.id.to_string(),
            name: p.name,
            tags: p.tags,
        })
    }

    pub fn peers(&self) -> Vec<FfiPeer> {
        self.node
            .peers()
            .into_iter()
            .map(|p| FfiPeer {
                id: p.id.to_string(),
                name: p.name,
                tags: p.tags,
            })
            .collect()
    }

    pub fn remove_peer(&self, id: String) -> Result<bool> {
        Ok(self.node.remove_peer(parse_id(&id)?)?)
    }

    pub fn link(&self, peer: String) -> Option<FfiLink> {
        let id = parse_id(&peer).ok()?;
        self.node.link(id).map(|(l, _)| l.into())
    }

    pub async fn send(&self, to: String, channel: String, body: Vec<u8>) -> Result<FfiLink> {
        Ok(self.node.send(parse_id(&to)?, &channel, body).await?.into())
    }

    pub async fn request(&self, to: String, channel: String, body: Vec<u8>) -> Result<Vec<u8>> {
        Ok(self
            .node
            .request(parse_id(&to)?, &channel, body)
            .await?
            .to_vec())
    }

    pub fn on_request(&self, channel: String, handler: Arc<dyn RequestHandler>) {
        self.node.on_request(&channel, move |from, body| {
            let h = handler.clone();
            async move {
                let out =
                    tokio::task::spawn_blocking(move || h.handle(from.to_string(), body.to_vec()))
                        .await
                        .map_err(|e| anyhow::anyhow!("handler panicked: {e}"))?;
                Ok(tethersys::Bytes::from(out))
            }
        });
    }

    pub async fn send_file(&self, to: String, path: String) -> Result<FfiFileOffer> {
        Ok(self.node.send_file(parse_id(&to)?, path).await?.into())
    }

    pub async fn accept_file(&self, offer: FfiFileOffer, dest: String) -> Result<String> {
        let offer: tethersys::FileOffer = offer.try_into()?;
        Ok(self
            .node
            .accept_file(&offer, dest)
            .await?
            .display()
            .to_string())
    }

    pub async fn subscribe(&self, topic: String) -> Result<()> {
        self.topic(&topic).await.map(|_| ())
    }

    pub async fn publish(&self, topic: String, body: Vec<u8>) -> Result<()> {
        Ok(self.topic(&topic).await?.publish(body).await?)
    }

    pub async fn space_set(&self, space: String, key: String, value: Vec<u8>) -> Result<()> {
        Ok(self.space(&space).await?.set(&key, value).await?)
    }

    pub async fn space_delete(&self, space: String, key: String) -> Result<()> {
        Ok(self.space(&space).await?.delete(&key).await?)
    }

    pub async fn space_get(&self, space: String, key: String) -> Result<Option<Vec<u8>>> {
        Ok(self.space(&space).await?.get(&key).map(|b| b.to_vec()))
    }

    pub async fn space_keys(&self, space: String) -> Result<Vec<String>> {
        Ok(self
            .space(&space)
            .await?
            .entries()
            .into_iter()
            .map(|(k, _)| k)
            .collect())
    }

    /// Forward a loopback TCP port to `peer`, which serves TCP. Returns the port on
    /// 127.0.0.1 to connect to; asking again for the same peer returns the same port.
    pub async fn forward_tcp(&self, peer: String) -> Result<u16> {
        let id = parse_id(&peer)?;
        let mut f = self.forwards.lock().await;
        if let Some(fwd) = f.get(&id) {
            return Ok(fwd.local_addr().port());
        }
        let fwd = self
            .node
            .forward_tcp(id, std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
            .await?;
        let port = fwd.local_addr().port();
        f.insert(id, fwd);
        Ok(port)
    }

    /// Close the forward to `peer`, if there is one.
    pub async fn stop_forward(&self, peer: String) -> Result<bool> {
        Ok(self
            .forwards
            .lock()
            .await
            .remove(&parse_id(&peer)?)
            .is_some())
    }

    pub async fn check_mailbox(&self) -> Result<u32> {
        Ok(self.node.check_mailbox().await? as u32)
    }

    /// Lease a tunnel and return a wg-quick config to hand to the platform VPN API.
    pub async fn tunnel_config(&self) -> Result<String> {
        Ok(self.node.tunnel().await?.wg_quick_config())
    }

    pub async fn shutdown(&self) -> Result<()> {
        Ok(self.node.clone().shutdown().await?)
    }
}
