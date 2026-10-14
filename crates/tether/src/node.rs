//! The node: one endpoint, every layer wired together.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock, Weak},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use iroh::{
    Endpoint, EndpointAddr, RelayConfig, RelayMap, RelayMode, RelayUrl, SecretKey, Watcher,
    address_lookup::{DnsAddressLookup, MemoryLookup, PkarrPublisher, PkarrResolver},
    endpoint::{Connection, presets},
    protocol::{DynProtocolHandler, Router},
};
use iroh_blobs::{BlobsProtocol, api::Store};
use iroh_gossip::Gossip;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::{
    events::{Event, LinkKind},
    files::FileOffer,
    identity::{self, BoxKey, NodeId},
    messaging::{Delivery, MessagingHandler, RequestHandler, Seen},
    pairing::{Invite, Invites, PairingHandler},
    pubsub::Topic,
    svc::{ServerTicket, SvcReq, SvcResp},
    sync::{Space, SpaceState, SyncHandler},
    trust::{Peer, TrustGate, TrustMode, TrustStore},
    tunnel::{Tunnel, WgKeypair},
};

/// Which discovery layers are on. Each one works alone; together they cover more networks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Discovery {
    /// Publish and resolve addresses via the public n0 DNS (pkarr) service.
    pub n0_dns: bool,
    /// Find peers on the same LAN with multicast DNS. No internet needed.
    pub mdns: bool,
    /// Publish and resolve via the BitTorrent Mainline DHT. No company in the loop.
    pub dht: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Relays {
    /// The free public n0 relays.
    Public,
    /// Only these relays (url, optional access token).
    Custom(Vec<(RelayUrl, Option<String>)>),
    /// Public relays plus these.
    PublicAnd(Vec<(RelayUrl, Option<String>)>),
    /// No relays at all: direct paths only.
    Disabled,
}

/// Ready-made layer combinations. Start from one and override fields as needed.
#[derive(Debug, Clone)]
pub enum Profile {
    /// Zero setup: public relays, DNS, DHT and LAN discovery.
    Public,
    /// Everything in `Public` plus your own server for relay, mailbox and directory.
    Hybrid(ServerTicket),
    /// Only your own infrastructure plus LAN and DHT. No third-party services.
    SelfHosted(ServerTicket),
    /// LAN only. Works with no internet at all.
    Local,
    /// No servers of any kind: DHT and LAN discovery, direct paths only.
    Sovereign,
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Human-readable device name shown to peers when pairing.
    pub name: String,
    /// Where identity, trust, files and spaces persist. `None` keeps everything in memory.
    pub data_dir: Option<PathBuf>,
    /// Supply the identity directly (for example from the OS keychain) instead of a file.
    pub secret_key: Option<SecretKey>,
    pub discovery: Discovery,
    pub relays: Relays,
    pub server: Option<ServerTicket>,
    /// Route through the server's relay when it has one.
    pub use_server_relay: bool,
    pub trust: TrustMode,
    pub connect_timeout: Duration,
    /// Download offered files automatically into this directory.
    pub auto_accept_files: Option<PathBuf>,
    pub sync_interval: Duration,
    /// How often to poll the server mailbox and refresh our directory entry.
    pub server_poll: Duration,
    /// Fixed UDP port to bind (useful behind port forwards). `None` picks one.
    pub port: Option<u16>,
    /// Never use direct paths, only relays. Peers never learn this device's IP address.
    /// Costs latency and bandwidth; useful for privacy-sensitive apps.
    pub hide_ip: bool,
    /// Test builds only: accept relays with self-signed certificates.
    #[cfg(feature = "test-utils")]
    pub insecure_relay_tls: bool,
}

impl Config {
    pub fn new(name: impl Into<String>, profile: Profile) -> Self {
        let all = Discovery {
            n0_dns: true,
            mdns: true,
            dht: true,
        };
        let (discovery, relays, server) = match profile {
            Profile::Public => (all, Relays::Public, None),
            Profile::Hybrid(t) => (all, Relays::Public, Some(t)),
            Profile::SelfHosted(t) => (
                Discovery {
                    n0_dns: false,
                    ..all
                },
                Relays::Custom(vec![]),
                Some(t),
            ),
            Profile::Local => (
                Discovery {
                    n0_dns: false,
                    mdns: true,
                    dht: false,
                },
                Relays::Disabled,
                None,
            ),
            Profile::Sovereign => (
                Discovery {
                    n0_dns: false,
                    ..all
                },
                Relays::Disabled,
                None,
            ),
        };
        Self {
            name: name.into(),
            data_dir: None,
            secret_key: None,
            discovery,
            relays,
            server,
            use_server_relay: true,
            trust: TrustMode::Pinned,
            connect_timeout: Duration::from_secs(10),
            auto_accept_files: None,
            sync_interval: crate::sync::default_interval(),
            server_poll: Duration::from_secs(30),
            port: None,
            hide_ip: false,
            #[cfg(feature = "test-utils")]
            insecure_relay_tls: false,
        }
    }

    pub fn data_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.data_dir = Some(dir.into());
        self
    }

    fn relay_mode(&self) -> RelayMode {
        let list_to_map = |list: &[(RelayUrl, Option<String>)]| {
            let map = RelayMap::empty();
            for (url, token) in list {
                let mut cfg = RelayConfig::from(url.clone());
                if let Some(t) = token {
                    cfg = cfg.with_auth_token(t.clone());
                }
                map.insert(url.clone(), Arc::new(cfg));
            }
            map
        };
        let map = match &self.relays {
            Relays::Disabled => return RelayMode::Disabled,
            Relays::Public => iroh::defaults::prod::default_relay_map(),
            Relays::Custom(list) => list_to_map(list),
            Relays::PublicAnd(list) => {
                let m = iroh::defaults::prod::default_relay_map();
                m.extend(&list_to_map(list));
                m
            }
        };
        if self.use_server_relay
            && let Some(ServerTicket {
                relay: Some(url),
                token,
                ..
            }) = &self.server
        {
            let cfg = RelayConfig::from(url.clone()).with_auth_token(token.clone());
            map.insert(url.clone(), Arc::new(cfg));
        }
        if map.is_empty() {
            RelayMode::Disabled
        } else {
            RelayMode::Custom(map)
        }
    }
}

/// Shared state behind a [`Node`]. Protocol handlers hold this, never the router.
pub(crate) struct Inner {
    pub ep: Endpoint,
    pub cfg: Config,
    pub name: String,
    pub trust: Arc<TrustStore>,
    pub box_key: BoxKey,
    pub events: broadcast::Sender<Event>,
    pub invites: Invites,
    pub memory: MemoryLookup,
    pub seen: Seen,
    pub blobs: Store,
    pub gossip: Gossip,
    pub spaces: Mutex<HashMap<String, Arc<SpaceState>>>,
    #[allow(clippy::type_complexity)]
    pub handlers: RwLock<HashMap<String, RequestHandler>>,
    pool: Mutex<HashMap<(NodeId, &'static [u8]), Connection>>,
    me: Weak<Inner>,
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Node")
            .field("id", &self.ep.id())
            .field("name", &self.name)
            .finish()
    }
}

/// Which path the selected QUIC path uses right now.
pub(crate) fn link_of(conn: &Connection) -> LinkKind {
    let paths = conn.paths();
    let selected = paths.iter().find(|p| p.is_selected());
    match selected {
        Some(p) if p.is_ip() => LinkKind::Direct,
        _ => LinkKind::Relayed,
    }
}

fn rtt_of(conn: &Connection) -> u64 {
    conn.paths()
        .iter()
        .find(|p| p.is_selected())
        .map(|p| p.rtt().as_millis() as u64)
        .unwrap_or(0)
}

impl Inner {
    pub(crate) fn self_arc(&self) -> Arc<Inner> {
        self.me
            .upgrade()
            .expect("node is alive while its handlers run")
    }

    pub(crate) fn server_id(&self) -> Option<NodeId> {
        self.cfg.server.as_ref().map(|t| t.addr.id)
    }

    /// Feed the last known address of a peer into the lookup so dialing by id can use it.
    pub(crate) async fn prime_addr(&self, id: NodeId) {
        if self.memory.get_endpoint_info(id).is_some() {
            return;
        }
        if let Some(addr) = self.trust.get(&id).and_then(|p| p.last_addr) {
            self.memory.add_endpoint_info(addr);
        } else if let Some(t) = &self.cfg.server
            && t.addr.id == id
        {
            self.memory.add_endpoint_info(t.addr.clone());
        }
    }

    /// Dial a peer, climbing the ladder: pooled connection, then every discovery layer
    /// (memory, LAN, DNS, DHT) in parallel, then the server directory.
    pub(crate) async fn connect(&self, id: NodeId, alpn: &'static [u8]) -> Result<Connection> {
        if let Some(c) = self.pool.lock().unwrap().get(&(id, alpn))
            && c.close_reason().is_none()
        {
            return Ok(c.clone());
        }
        if id == self.ep.id() {
            bail!("cannot connect to ourselves");
        }
        if !self.trust.is_allowed(&id) {
            bail!("{} is not a trusted peer; pair first", id.fmt_short());
        }
        self.prime_addr(id).await;
        let timeout = self.cfg.connect_timeout;
        let first = tokio::time::timeout(timeout, self.ep.connect(id, alpn)).await;
        let conn = match first {
            Ok(Ok(c)) => c,
            other => {
                let err = match other {
                    Ok(Err(e)) => anyhow!(e),
                    _ => anyhow!("timed out after {timeout:?}"),
                };
                // Rung two: the directory may know a fresher address than DNS/DHT.
                let Some(addr) = Box::pin(self.directory_lookup(id)).await else {
                    return Err(err.context(format!("could not reach {}", id.fmt_short())));
                };
                self.memory.add_endpoint_info(addr.clone());
                tokio::time::timeout(timeout, self.ep.connect(addr, alpn))
                    .await
                    .map_err(|_| anyhow!("timed out reaching {}", id.fmt_short()))?
                    .with_context(|| format!("could not reach {}", id.fmt_short()))?
            }
        };
        self.pool.lock().unwrap().insert((id, alpn), conn.clone());
        self.watch_link(id, &conn);
        Ok(conn)
    }

    pub(crate) fn forget(&self, id: NodeId, alpn: &'static [u8]) {
        self.pool.lock().unwrap().remove(&(id, alpn));
    }

    /// Report a connection and every later change of its path (relay <-> direct).
    pub(crate) fn watch_link(&self, peer: NodeId, conn: &Connection) {
        if Some(peer) == self.server_id() {
            return;
        }
        let conn = conn.clone();
        let events = self.events.clone();
        tokio::spawn(async move {
            let mut last = link_of(&conn);
            let _ = events.send(Event::Connected { peer, link: last });
            loop {
                tokio::select! {
                    _ = conn.closed() => break,
                    _ = tokio::time::sleep(Duration::from_secs(2)) => {}
                }
                let now = link_of(&conn);
                if now != last {
                    last = now;
                    let _ = events.send(Event::LinkChanged {
                        peer,
                        link: now,
                        rtt_ms: rtt_of(&conn),
                    });
                }
            }
        });
    }

    pub(crate) async fn svc(&self, req: SvcReq) -> Result<SvcResp> {
        let server = self
            .server_id()
            .ok_or_else(|| anyhow!("no server configured"))?;
        let mut last = None;
        for _ in 0..2 {
            let conn = self.connect(server, crate::svc::ALPN).await?;
            match crate::wire::call::<_, SvcResp>(&conn, &req).await {
                Ok(r) => return r.into_result(),
                Err(e) => {
                    self.forget(server, crate::svc::ALPN);
                    last = Some(e);
                }
            }
        }
        Err(last.expect("loop ran"))
    }

    async fn directory_lookup(&self, id: NodeId) -> Option<EndpointAddr> {
        if self.server_id().is_none() || Some(id) == self.server_id() {
            return None;
        }
        match self.svc(SvcReq::Lookup { id }).await {
            Ok(SvcResp::Addr(Some(a))) if a.id == id => Some(a),
            _ => None,
        }
    }

    pub(crate) async fn pin_on_server(&self, hash: iroh_blobs::Hash) -> Result<()> {
        self.svc(SvcReq::PinBlob {
            hash: hash.to_string(),
        })
        .await
        .map(|_| ())
    }

    async fn register(&self) -> Result<()> {
        let t = self
            .cfg
            .server
            .as_ref()
            .ok_or_else(|| anyhow!("no server"))?;
        self.svc(SvcReq::Register {
            token: t.token.clone(),
            addr: self.ep.addr(),
            name: self.name.clone(),
        })
        .await
        .map(|_| ())
    }

    /// Keep our directory entry fresh and drain the mailbox.
    fn spawn_server_loop(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        let mut addr_watch = self.ep.watch_addr();
        let poll = self.cfg.server_poll;
        tokio::spawn(async move {
            let mut ok = false;
            loop {
                let Some(inner) = weak.upgrade() else { break };
                let result = async {
                    inner.register().await?;
                    inner.mailbox_drain().await
                }
                .await;
                match (&result, ok) {
                    (Ok(_), false) => {
                        let _ = inner.events.send(Event::Server {
                            connected: true,
                            detail: "registered".into(),
                        });
                        ok = true;
                    }
                    (Err(e), true) => {
                        let _ = inner.events.send(Event::Server {
                            connected: false,
                            detail: format!("{e:#}"),
                        });
                        ok = false;
                    }
                    _ => {}
                }
                drop(inner);
                // Wake on schedule, or right away when our address changes (new network).
                tokio::select! {
                    _ = tokio::time::sleep(poll) => {}
                    r = addr_watch.updated() => if r.is_err() { break },
                }
            }
        });
    }
}

/// A running node. Cheap to clone.
#[derive(Debug, Clone)]
pub struct Node {
    inner: Arc<Inner>,
    router: Router,
    _store: Arc<StoreKeepalive>,
}

#[derive(Debug)]
enum StoreKeepalive {
    Fs(#[allow(dead_code)] iroh_blobs::store::fs::FsStore),
    Mem(#[allow(dead_code)] iroh_blobs::store::mem::MemStore),
}

/// Start a node with extra protocols of your own alongside the built-in ones.
pub struct NodeBuilder {
    cfg: Config,
    extra: Vec<(Vec<u8>, Box<dyn DynProtocolHandler>)>,
}

impl NodeBuilder {
    /// Serve your own protocol on `alpn`. It sits behind the same trust gate as the rest.
    pub fn protocol(
        mut self,
        alpn: impl AsRef<[u8]>,
        handler: impl Into<Box<dyn DynProtocolHandler>>,
    ) -> Self {
        self.extra.push((alpn.as_ref().to_vec(), handler.into()));
        self
    }

    pub async fn spawn(self) -> Result<Node> {
        Node::start(self.cfg, self.extra).await
    }
}

impl Node {
    pub fn builder(cfg: Config) -> NodeBuilder {
        NodeBuilder {
            cfg,
            extra: Vec::new(),
        }
    }

    pub async fn spawn(cfg: Config) -> Result<Node> {
        Self::start(cfg, Vec::new()).await
    }

    async fn start(
        cfg: Config,
        extra: Vec<(Vec<u8>, Box<dyn DynProtocolHandler>)>,
    ) -> Result<Node> {
        let dir = cfg.data_dir.clone();
        if let Some(d) = &dir {
            std::fs::create_dir_all(d).with_context(|| format!("create {}", d.display()))?;
        }
        let secret = match (&cfg.secret_key, &dir) {
            (Some(k), _) => k.clone(),
            (None, Some(d)) => identity::load_or_create(&d.join("identity.key"))?,
            (None, None) => SecretKey::generate(),
        };
        let trust = TrustStore::open(dir.as_ref().map(|d| d.join("trust.json")), cfg.trust)?;
        if let Some(t) = &cfg.server {
            trust.allow_infra(t.addr.id);
        }

        let memory = MemoryLookup::new();
        let mut b = Endpoint::builder(presets::Minimal)
            .secret_key(secret.clone())
            .relay_mode(cfg.relay_mode())
            .address_lookup(memory.clone())
            .hooks(TrustGate(trust.clone()));
        if cfg.discovery.n0_dns {
            b = b
                .address_lookup(PkarrPublisher::n0_dns())
                .address_lookup(PkarrResolver::n0_dns())
                .address_lookup(DnsAddressLookup::n0_dns());
        }
        if cfg.discovery.mdns {
            b = b.address_lookup(iroh_mdns_address_lookup::MdnsAddressLookup::builder());
        }
        if cfg.discovery.dht {
            b = b.address_lookup(iroh_mainline_address_lookup::DhtAddressLookup::builder());
        }
        if cfg.hide_ip {
            b = b.clear_ip_transports();
        }
        #[cfg(feature = "test-utils")]
        if cfg.insecure_relay_tls {
            b = b.ca_tls_config(iroh::tls::CaTlsConfig::insecure_skip_verify());
        }
        if let Some(port) = cfg.port {
            b = b
                .bind_addr(std::net::SocketAddr::from(([0, 0, 0, 0], port)))
                .map_err(|e| anyhow!("bind port {port}: {e}"))?;
        }
        let ep = b.bind().await.map_err(|e| anyhow!("bind endpoint: {e}"))?;
        for p in trust.list() {
            if let Some(a) = p.last_addr {
                memory.add_endpoint_info(a);
            }
        }

        let (store, keep) = match &dir {
            Some(d) => {
                let fs = iroh_blobs::store::fs::FsStore::load(d.join("blobs"))
                    .await
                    .map_err(|e| anyhow!("open blob store: {e}"))?;
                ((*fs).clone(), StoreKeepalive::Fs(fs))
            }
            None => {
                let mem = iroh_blobs::store::mem::MemStore::new();
                ((*mem).clone(), StoreKeepalive::Mem(mem))
            }
        };
        let gossip = Gossip::builder().spawn(ep.clone());
        let (events, _) = broadcast::channel(1024);

        let inner = Arc::new_cyclic(|me| Inner {
            ep: ep.clone(),
            name: cfg.name.clone(),
            box_key: BoxKey::derive(&secret),
            cfg,
            trust,
            events,
            invites: Invites::default(),
            memory,
            seen: Seen::default(),
            blobs: store.clone(),
            gossip: gossip.clone(),
            spaces: Mutex::new(HashMap::new()),
            handlers: RwLock::new(HashMap::new()),
            pool: Mutex::new(HashMap::new()),
            me: me.clone(),
        });

        let mut rb = Router::builder(ep)
            .accept(crate::pairing::ALPN, PairingHandler(inner.clone()))
            .accept(crate::messaging::ALPN, MessagingHandler(inner.clone()))
            .accept(crate::sync::ALPN, SyncHandler(inner.clone()))
            .accept(iroh_blobs::ALPN, BlobsProtocol::new(&store, None))
            .accept(iroh_gossip::ALPN, gossip);
        for (alpn, h) in extra {
            rb = rb.accept(alpn, h);
        }
        let router = rb.spawn();

        if inner.cfg.server.is_some() {
            inner.spawn_server_loop();
        }
        Ok(Node {
            inner,
            router,
            _store: Arc::new(keep),
        })
    }

    // ---- identity & status ------------------------------------------------------------

    pub fn id(&self) -> NodeId {
        self.inner.ep.id()
    }

    pub fn name(&self) -> &str {
        &self.inner.name
    }

    /// Our current address (relay URL plus any direct IPs). Changes as networks change.
    pub fn addr(&self) -> EndpointAddr {
        self.inner.ep.addr()
    }

    /// Wait until the node has a relay connection (or a direct address when relays are off).
    pub async fn online(&self, timeout: Duration) -> bool {
        tokio::time::timeout(timeout, self.inner.ep.online())
            .await
            .is_ok()
    }

    pub fn events(&self) -> broadcast::Receiver<Event> {
        self.inner.events.subscribe()
    }

    /// The raw iroh endpoint, for apps that want to go below this crate.
    pub fn endpoint(&self) -> &Endpoint {
        &self.inner.ep
    }

    /// How we currently reach a peer, if a connection is open.
    pub fn link(&self, peer: NodeId) -> Option<(LinkKind, u64)> {
        let pool = self.inner.pool.lock().unwrap();
        pool.iter()
            .filter(|((id, _), c)| *id == peer && c.close_reason().is_none())
            .map(|(_, c)| (link_of(c), rtt_of(c)))
            .next()
    }

    // ---- pairing & trust --------------------------------------------------------------

    /// Create an invite string (put it in a QR code or a link). Expires after `ttl`,
    /// and stops working after `uses` redemptions.
    pub fn invite(&self, ttl: Duration, uses: u32) -> Invite {
        self.inner.create_invite(ttl, uses, Vec::new())
    }

    /// Invite whose redeemer gets these tags in our trust store (for roles or groups).
    pub fn invite_tagged(&self, ttl: Duration, uses: u32, tags: Vec<String>) -> Invite {
        self.inner.create_invite(ttl, uses, tags)
    }

    /// Redeem an invite. On success both sides trust each other.
    pub async fn join(&self, invite: &str) -> Result<Peer> {
        self.inner.redeem_invite(&Invite::decode(invite)?).await
    }

    pub fn peers(&self) -> Vec<Peer> {
        self.inner.trust.list()
    }

    /// Trust a peer you verified some other way (for example provisioning at the factory).
    pub fn trust_peer(&self, peer: Peer) -> Result<()> {
        if let Some(a) = &peer.last_addr {
            self.inner.memory.add_endpoint_info(a.clone());
        }
        self.inner.trust.upsert(peer)
    }

    pub fn remove_peer(&self, id: NodeId) -> Result<bool> {
        self.inner.forget(id, crate::messaging::ALPN);
        self.inner.trust.remove(&id)
    }

    // ---- messaging --------------------------------------------------------------------

    /// Send with the default policy: live if possible, server mailbox if not.
    pub async fn send(
        &self,
        to: NodeId,
        channel: &str,
        body: impl Into<Bytes>,
    ) -> Result<LinkKind> {
        self.inner
            .send_message(to, channel, body.into(), Delivery::Auto)
            .await
    }

    pub async fn send_with(
        &self,
        to: NodeId,
        channel: &str,
        body: impl Into<Bytes>,
        delivery: Delivery,
    ) -> Result<LinkKind> {
        self.inner
            .send_message(to, channel, body.into(), delivery)
            .await
    }

    /// Call a peer's handler for `channel` and wait for its reply. Live only.
    pub async fn request(
        &self,
        to: NodeId,
        channel: &str,
        body: impl Into<Bytes>,
    ) -> Result<Bytes> {
        self.inner.request(to, channel, body.into()).await
    }

    /// Answer requests on `channel`. Messages on a channel with a handler go to the
    /// handler instead of the event stream.
    pub fn on_request<F, Fut>(&self, channel: &str, f: F)
    where
        F: Fn(NodeId, Bytes) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<Bytes>> + Send + 'static,
    {
        let h: RequestHandler = Arc::new(move |from, body| Box::pin(f(from, body)));
        self.inner
            .handlers
            .write()
            .unwrap()
            .insert(channel.to_string(), h);
    }

    /// Check the server mailbox right now instead of waiting for the next poll.
    pub async fn check_mailbox(&self) -> Result<usize> {
        self.inner.mailbox_drain().await
    }

    // ---- files ------------------------------------------------------------------------

    pub async fn send_file(&self, to: NodeId, path: impl AsRef<Path>) -> Result<FileOffer> {
        Ok(self
            .inner
            .send_file(to, path.as_ref(), Delivery::Auto)
            .await?
            .0)
    }

    pub async fn send_file_with(
        &self,
        to: NodeId,
        path: impl AsRef<Path>,
        delivery: Delivery,
    ) -> Result<(FileOffer, LinkKind)> {
        self.inner.send_file(to, path.as_ref(), delivery).await
    }

    /// Download an offered file to `dest`. Progress arrives as events.
    pub async fn accept_file(&self, offer: &FileOffer, dest: impl AsRef<Path>) -> Result<PathBuf> {
        self.inner.fetch_file(offer, dest.as_ref()).await
    }

    pub async fn purge_file(&self, hash: &str) -> Result<()> {
        self.inner.purge_file(hash).await
    }

    // ---- pub/sub & sync ---------------------------------------------------------------

    /// Join a topic with all trusted peers as bootstrap.
    pub async fn topic(&self, name: &str) -> Result<Topic> {
        self.inner.join_topic(name, None).await
    }

    pub async fn topic_with(&self, name: &str, bootstrap: Vec<NodeId>) -> Result<Topic> {
        self.inner.join_topic(name, Some(bootstrap)).await
    }

    /// Open a replicated space shared with all trusted peers.
    pub async fn space(&self, name: &str) -> Result<Space> {
        self.inner.open_space(name, None).await
    }

    /// Open a space restricted to these members.
    pub async fn space_with(&self, name: &str, members: Vec<NodeId>) -> Result<Space> {
        self.inner.open_space(name, Some(members)).await
    }

    // ---- tunnels ----------------------------------------------------------------------

    /// Lease a WireGuard address on the server hub and get a ready-to-import config.
    pub async fn tunnel(&self) -> Result<Tunnel> {
        self.inner.lease_tunnel(None).await
    }

    /// Lease with an existing keypair (reuse the platform tunnel's key across renewals).
    pub async fn tunnel_with_keys(&self, keys: WgKeypair) -> Result<Tunnel> {
        self.inner.lease_tunnel(Some(keys)).await
    }

    pub async fn release_tunnel(&self) -> Result<()> {
        self.inner.release_tunnel().await
    }

    pub async fn tunnel_peers(&self) -> Result<Vec<(NodeId, String)>> {
        self.inner.tunnel_peers().await
    }

    pub async fn shutdown(self) -> Result<()> {
        self.router
            .shutdown()
            .await
            .map_err(|e| anyhow!("shutdown: {e}"))
    }
}
