//! tethersysd: the optional server for tethersys networks.
//!
//! It is one iroh endpoint that offers four services to members of one network:
//!
//! - **Directory**: the latest address each member registered, for when DNS/DHT are stale.
//! - **Mailbox**: sealed envelopes held for offline members. Opaque to the server.
//! - **File cache**: pulls a blob from a sender so an offline receiver can fetch it later.
//! - **WireGuard hub** (optional): leases tunnel addresses for device-level networking.
//!
//! Relaying is done by the official `iroh-relay` binary next to it (see `deploy/`), which
//! uses the same network token as its access token.

pub mod state;
pub mod wg;

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow};
use iroh::{
    Endpoint, EndpointId, RelayConfig, RelayMap, RelayMode, RelayUrl, SecretKey,
    endpoint::{AfterHandshakeOutcome, Connection, EndpointHooks, VarInt, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use iroh_blobs::{BlobsProtocol, Hash, api::Tag, store::fs::FsStore};
use state::{Lease, Member, State, StoredMail};
use tethersys::{
    svc::{self, MailItem, ServerTicket, SvcReq, SvcResp, WgLease},
    wire::{now_ms, random_bytes, read_frame, write_frame},
};

pub struct Options {
    pub data_dir: PathBuf,
    pub port: u16,
    /// Network token. Generated and stored on first launch when `None`.
    pub token: Option<String>,
    /// URL of the relay running next to this server, if any.
    pub relay: Option<RelayUrl>,
    /// Public IP:port to advertise, for direct dialing without a relay hop.
    pub public_addr: Option<SocketAddr>,
    pub mail_ttl: Duration,
    pub mail_max_per_member: usize,
    pub mail_max_bytes: usize,
    pub blob_ttl: Duration,
    pub wg: Option<wg::Hub>,
    pub wg_lease: Duration,
}

impl Options {
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
            port: 47711,
            token: None,
            relay: None,
            public_addr: None,
            mail_ttl: Duration::from_secs(14 * 24 * 3600),
            mail_max_per_member: 2000,
            mail_max_bytes: 1024 * 1024,
            blob_ttl: Duration::from_secs(72 * 3600),
            wg: None,
            wg_lease: Duration::from_secs(24 * 3600),
        }
    }
}

struct Ctx {
    ep: Endpoint,
    state: State,
    token: String,
    store: FsStore,
    opts: Options,
}

pub struct Server {
    router: Router,
    ctx: Arc<Ctx>,
}

/// Members only, except the control protocol itself (Register checks the token there).
#[derive(Debug, Clone)]
struct Gate(Arc<std::sync::Mutex<Option<std::sync::Weak<Ctx>>>>);

impl EndpointHooks for Gate {
    async fn after_handshake<'a>(&'a self, conn: &'a Connection) -> AfterHandshakeOutcome {
        if conn.alpn() == svc::ALPN {
            return AfterHandshakeOutcome::accept();
        }
        let ctx = self.0.lock().unwrap().as_ref().and_then(|w| w.upgrade());
        let id = conn.remote_id();
        match ctx {
            Some(c) if c.state.is_member(&id) => AfterHandshakeOutcome::accept(),
            _ => AfterHandshakeOutcome::Reject {
                error_code: VarInt::from_u32(403),
                reason: b"not a member".to_vec(),
            },
        }
    }
}

fn load_secret(path: &std::path::Path) -> Result<SecretKey> {
    tethersys::identity::load_or_create(path)
}

fn load_token(dir: &std::path::Path, given: Option<String>) -> Result<String> {
    if let Some(t) = given {
        return Ok(t);
    }
    let path = dir.join("token");
    if let Ok(t) = std::fs::read_to_string(&path) {
        return Ok(t.trim().to_string());
    }
    let t = data_encoding::BASE32_NOPAD
        .encode(&random_bytes::<20>())
        .to_lowercase();
    std::fs::write(&path, &t)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(t)
}

impl Server {
    pub async fn spawn(opts: Options) -> Result<Self> {
        std::fs::create_dir_all(&opts.data_dir)?;
        let secret = load_secret(&opts.data_dir.join("identity.key"))?;
        let token = load_token(&opts.data_dir, opts.token.clone())?;
        let state = State::load(opts.data_dir.join("state.bin"))?;

        let relay_mode = match &opts.relay {
            Some(url) => {
                let map = RelayMap::empty();
                map.insert(
                    url.clone(),
                    Arc::new(RelayConfig::from(url.clone()).with_auth_token(token.clone())),
                );
                RelayMode::Custom(map)
            }
            None => RelayMode::Disabled,
        };
        let gate = Gate(Default::default());
        let mut b = Endpoint::builder(presets::Minimal)
            .secret_key(secret)
            .relay_mode(relay_mode)
            .hooks(gate.clone())
            .bind_addr(SocketAddr::from(([0, 0, 0, 0], opts.port)))
            .map_err(|e| anyhow!("bind port {}: {e}", opts.port))?;
        if let Some(a) = opts.public_addr {
            b = b.external_addr(a);
        }
        let ep = b.bind().await.map_err(|e| anyhow!("bind: {e}"))?;

        let mut store_opts =
            iroh_blobs::store::fs::options::Options::new(&opts.data_dir.join("blobs"));
        store_opts.gc = Some(iroh_blobs::store::GcConfig {
            interval: Duration::from_secs(300),
            add_protected: None,
        });
        let store =
            FsStore::load_with_opts(opts.data_dir.join("blobs").join("blobs.db"), store_opts)
                .await
                .map_err(|e| anyhow!("open blob store: {e}"))?;

        let ctx = Arc::new(Ctx {
            ep: ep.clone(),
            state,
            token,
            store,
            opts,
        });
        *gate.0.lock().unwrap() = Some(Arc::downgrade(&ctx));
        ctx.reapply_leases();

        let router = Router::builder(ep)
            .accept(svc::ALPN, Handler(ctx.clone()))
            .accept(iroh_blobs::ALPN, BlobsProtocol::new(&ctx.store, None))
            .spawn();

        let weak = Arc::downgrade(&ctx);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                let Some(ctx) = weak.upgrade() else { break };
                if let Err(e) = ctx.maintain().await {
                    tracing::warn!("maintenance: {e:#}");
                }
            }
        });
        Ok(Self { router, ctx })
    }

    pub fn id(&self) -> EndpointId {
        self.ctx.ep.id()
    }

    /// The string apps paste into their config to use this server.
    pub fn ticket(&self) -> ServerTicket {
        ServerTicket {
            addr: self.ctx.ep.addr(),
            relay: self.ctx.opts.relay.clone(),
            token: self.ctx.token.clone(),
        }
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.ctx.ep
    }

    pub fn member_count(&self) -> usize {
        self.ctx.state.data.lock().unwrap().members.len()
    }

    /// Run expiry now (normally runs every minute).
    pub async fn maintain(&self) -> Result<()> {
        self.ctx.maintain().await
    }

    pub async fn shutdown(self) -> Result<()> {
        self.router.shutdown().await.map_err(|e| anyhow!("{e}"))
    }
}

#[derive(Clone)]
struct Handler(Arc<Ctx>);

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("tethersysd")
    }
}

impl ProtocolHandler for Handler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let peer = conn.remote_id();
        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
            let ctx = self.0.clone();
            tokio::spawn(async move {
                let resp = match read_frame::<SvcReq>(&mut recv).await {
                    Ok(req) => ctx
                        .handle(peer, req)
                        .await
                        .unwrap_or_else(|e| SvcResp::Error(format!("{e:#}"))),
                    Err(e) => SvcResp::Error(e.to_string()),
                };
                let _ = write_frame(&mut send, &resp).await;
                let _ = send.finish();
                let _ = send.stopped().await;
            });
        }
        Ok(())
    }
}

fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

impl Ctx {
    async fn handle(&self, peer: EndpointId, req: SvcReq) -> Result<SvcResp> {
        if let SvcReq::Register {
            token,
            mut addr,
            name,
        } = req
        {
            if !ct_eq(&token, &self.token) {
                anyhow::bail!("wrong network token");
            }
            addr.id = peer;
            self.state.update(|d| {
                d.members.insert(
                    peer,
                    Member {
                        name,
                        addr: Some(addr),
                        last_seen_ms: now_ms(),
                    },
                );
            })?;
            return Ok(SvcResp::Ok);
        }
        if !self.state.is_member(&peer) {
            anyhow::bail!("register with the network token first");
        }
        Ok(match req {
            SvcReq::Register { .. } => unreachable!(),
            SvcReq::Lookup { id } => {
                let d = self.state.data.lock().unwrap();
                SvcResp::Addr(d.members.get(&id).and_then(|m| m.addr.clone()))
            }
            SvcReq::MailPut { to, envelope } => {
                if envelope.len() > self.opts.mail_max_bytes {
                    anyhow::bail!("envelope over {} bytes", self.opts.mail_max_bytes);
                }
                let max = self.opts.mail_max_per_member;
                self.state.update(|d| {
                    if !d.members.contains_key(&to) {
                        return Err(anyhow!("recipient is not a member of this network"));
                    }
                    let q = d.mail.entry(to).or_default();
                    if q.len() >= max {
                        return Err(anyhow!("recipient mailbox is full"));
                    }
                    q.push_back(StoredMail {
                        item: MailItem {
                            id: random_bytes(),
                            envelope,
                        },
                        from: peer,
                        stored_ms: now_ms(),
                    });
                    Ok(())
                })??;
                SvcResp::Ok
            }
            SvcReq::MailFetch => {
                let d = self.state.data.lock().unwrap();
                let items = d
                    .mail
                    .get(&peer)
                    .map(|q| q.iter().take(200).map(|m| m.item.clone()).collect())
                    .unwrap_or_default();
                SvcResp::Mail(items)
            }
            SvcReq::MailAck { ids } => {
                self.state.update(|d| {
                    if let Some(q) = d.mail.get_mut(&peer) {
                        q.retain(|m| !ids.contains(&m.item.id));
                    }
                })?;
                SvcResp::Ok
            }
            SvcReq::PinBlob { hash } => {
                let hash: Hash = hash.parse().context("bad hash")?;
                let downloader = self.store.downloader(&self.ep);
                downloader
                    .download(hash, vec![peer])
                    .await
                    .map_err(|e| anyhow!("pull from sender failed: {e}"))?;
                let expires = now_ms() + self.opts.blob_ttl.as_millis() as u64;
                self.store
                    .tags()
                    .set(format!("pin/{expires:020}/{hash}"), hash)
                    .await?;
                SvcResp::Ok
            }
            SvcReq::WgLease { wg_pub } => SvcResp::Lease(self.lease(peer, wg_pub)?),
            SvcReq::WgRelease => {
                let hub = self.hub()?;
                let old = self.state.update(|d| d.leases.remove(&peer))?;
                if let Some(l) = old {
                    hub.remove_peer(&l.wg_pub)?;
                }
                SvcResp::Ok
            }
            SvcReq::WgPeers => {
                self.hub()?;
                let now = now_ms();
                let d = self.state.data.lock().unwrap();
                SvcResp::WgPeers(
                    d.leases
                        .iter()
                        .filter(|(id, l)| **id != peer && l.expires_ms > now)
                        .map(|(id, l)| (*id, std::net::Ipv4Addr::from(l.ip).to_string()))
                        .collect(),
                )
            }
        })
    }

    fn hub(&self) -> Result<&wg::Hub> {
        self.opts
            .wg
            .as_ref()
            .ok_or_else(|| anyhow!("this server does not offer tunnels"))
    }

    fn lease(&self, peer: EndpointId, wg_pub: String) -> Result<WgLease> {
        let hub = self.hub()?;
        if !wg::valid_key(&wg_pub) {
            anyhow::bail!("not a WireGuard public key");
        }
        let expires_ms = now_ms() + self.opts.wg_lease.as_millis() as u64;
        let (ip, replaced) = self.state.update(|d| {
            // Keep a device's address stable across renewals.
            let (ip, replaced) = match d.leases.get(&peer) {
                Some(l) => (l.ip, (l.wg_pub != wg_pub).then(|| l.wg_pub.clone())),
                None => {
                    let used: std::collections::HashSet<[u8; 4]> =
                        d.leases.values().map(|l| l.ip).collect();
                    let ip = (2..2 + hub.capacity())
                        .map(|h| hub.ip(h))
                        .find(|ip| !used.contains(ip))
                        .ok_or_else(|| anyhow!("tunnel address pool is exhausted"))?;
                    (ip, None)
                }
            };
            d.leases.insert(
                peer,
                Lease {
                    wg_pub: wg_pub.clone(),
                    ip,
                    expires_ms,
                },
            );
            Ok::<_, anyhow::Error>((ip, replaced))
        })??;
        if let Some(old) = replaced {
            let _ = hub.remove_peer(&old);
        }
        hub.add_peer(&wg_pub, ip)?;
        Ok(WgLease {
            address: format!("{}/32", std::net::Ipv4Addr::from(ip)),
            server_pub: hub.server_pub.clone(),
            endpoint: hub.endpoint.clone(),
            allowed_ips: hub.subnet(),
            expires_ms,
        })
    }

    /// Interface peers vanish on host reboot; leases in state do not. Put them back.
    fn reapply_leases(&self) {
        let Some(hub) = &self.opts.wg else { return };
        let now = now_ms();
        let leases: Vec<Lease> = self
            .state
            .data
            .lock()
            .unwrap()
            .leases
            .values()
            .cloned()
            .collect();
        for l in leases.into_iter().filter(|l| l.expires_ms > now) {
            if let Err(e) = hub.add_peer(&l.wg_pub, l.ip) {
                tracing::warn!("restore tunnel peer: {e:#}");
            }
        }
    }

    async fn maintain(&self) -> Result<()> {
        let now = now_ms();
        let ttl = self.opts.mail_ttl.as_millis() as u64;
        let expired = self.state.update(|d| {
            for q in d.mail.values_mut() {
                q.retain(|m| now.saturating_sub(m.stored_ms) < ttl);
            }
            d.mail.retain(|_, q| !q.is_empty());
            let dead: Vec<EndpointId> = d
                .leases
                .iter()
                .filter(|(_, l)| l.expires_ms <= now)
                .map(|(id, _)| *id)
                .collect();
            dead.iter()
                .filter_map(|id| d.leases.remove(id))
                .collect::<Vec<_>>()
        })?;
        if let Some(hub) = &self.opts.wg {
            for l in expired {
                let _ = hub.remove_peer(&l.wg_pub);
            }
        }
        // Pin tags sort by expiry, so one range delete clears every expired copy.
        self.store
            .tags()
            .delete_range(Tag::from("pin/")..Tag::from(format!("pin/{now:020}")))
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn token_compare() {
        assert!(super::ct_eq("abc", "abc"));
        assert!(!super::ct_eq("abc", "abd"));
        assert!(!super::ct_eq("abc", "abcd"));
    }
}
