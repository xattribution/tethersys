//! Who is allowed to talk to this node.
//!
//! Every connection is mutually authenticated by key during the QUIC/TLS handshake. The
//! trust gate then decides whether that key is allowed in. In `Pinned` mode (the default)
//! only paired peers, configured servers and the pairing protocol itself get through, so
//! an attacker who learns your NodeId still cannot open a session, sync, gossip or fetch
//! files.

use std::{
    collections::{BTreeMap, HashSet},
    path::PathBuf,
    sync::{Arc, RwLock},
};

use anyhow::Result;
use iroh::{
    EndpointAddr,
    endpoint::{AfterHandshakeOutcome, Connection, EndpointHooks, VarInt},
};
use serde::{Deserialize, Serialize};

use crate::{identity::NodeId, wire::now_ms};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TrustMode {
    /// Only paired peers and configured servers may connect.
    #[default]
    Pinned,
    /// Any authenticated key may connect. Use for public swarms; apps must do their own checks.
    Open,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Peer {
    pub id: NodeId,
    pub name: String,
    /// X25519 key used to seal mailbox envelopes to this peer.
    pub box_pub: Option<[u8; 32]>,
    /// Last address that worked. Lets reconnects skip discovery entirely.
    pub last_addr: Option<EndpointAddr>,
    pub added_ms: u64,
    /// Free-form labels the app can use for roles or groups.
    pub tags: Vec<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct TrustFile {
    peers: Vec<Peer>,
}

#[derive(Debug)]
pub struct TrustStore {
    path: Option<PathBuf>,
    mode: TrustMode,
    peers: RwLock<BTreeMap<NodeId, Peer>>,
    /// Infrastructure keys (tethersysd servers) that are always allowed.
    infra: RwLock<HashSet<NodeId>>,
}

impl TrustStore {
    pub fn open(path: Option<PathBuf>, mode: TrustMode) -> Result<Arc<Self>> {
        let mut peers = BTreeMap::new();
        if let Some(p) = &path
            && let Ok(text) = std::fs::read_to_string(p)
        {
            let file: TrustFile = serde_json::from_str(&text)?;
            for peer in file.peers {
                peers.insert(peer.id, peer);
            }
        }
        Ok(Arc::new(Self {
            path,
            mode,
            peers: RwLock::new(peers),
            infra: RwLock::new(HashSet::new()),
        }))
    }

    pub fn mode(&self) -> TrustMode {
        self.mode
    }

    pub fn is_allowed(&self, id: &NodeId) -> bool {
        self.mode == TrustMode::Open
            || self.peers.read().unwrap().contains_key(id)
            || self.infra.read().unwrap().contains(id)
    }

    pub fn is_peer(&self, id: &NodeId) -> bool {
        self.peers.read().unwrap().contains_key(id)
    }

    pub fn allow_infra(&self, id: NodeId) {
        self.infra.write().unwrap().insert(id);
    }

    pub fn get(&self, id: &NodeId) -> Option<Peer> {
        self.peers.read().unwrap().get(id).cloned()
    }

    pub fn list(&self) -> Vec<Peer> {
        self.peers.read().unwrap().values().cloned().collect()
    }

    /// Add or update a peer, keeping fields the caller left empty.
    pub fn upsert(&self, mut peer: Peer) -> Result<()> {
        {
            let mut peers = self.peers.write().unwrap();
            if let Some(old) = peers.get(&peer.id) {
                if peer.box_pub.is_none() {
                    peer.box_pub = old.box_pub;
                }
                if peer.last_addr.is_none() {
                    peer.last_addr = old.last_addr.clone();
                }
                if peer.tags.is_empty() {
                    peer.tags = old.tags.clone();
                }
                peer.added_ms = old.added_ms;
            }
            if peer.added_ms == 0 {
                peer.added_ms = now_ms();
            }
            peers.insert(peer.id, peer);
        }
        self.save()
    }

    pub fn remember_addr(&self, addr: EndpointAddr) {
        let changed = {
            let mut peers = self.peers.write().unwrap();
            match peers.get_mut(&addr.id) {
                Some(p) if p.last_addr.as_ref() != Some(&addr) && !addr.is_empty() => {
                    p.last_addr = Some(addr);
                    true
                }
                _ => false,
            }
        };
        if changed {
            let _ = self.save();
        }
    }

    pub fn remove(&self, id: &NodeId) -> Result<bool> {
        let removed = self.peers.write().unwrap().remove(id).is_some();
        if removed {
            self.save()?;
        }
        Ok(removed)
    }

    fn save(&self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let file = TrustFile { peers: self.list() };
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&file)?)?;
        std::fs::rename(tmp, path)?;
        Ok(())
    }
}

/// ALPNs that unknown keys may use. Pairing has to work before trust exists.
pub(crate) const PUBLIC_ALPNS: &[&[u8]] = &[crate::pairing::ALPN];

/// Endpoint hook that enforces the trust store on every incoming and outgoing connection.
#[derive(Debug, Clone)]
pub(crate) struct TrustGate(pub Arc<TrustStore>);

impl EndpointHooks for TrustGate {
    async fn after_handshake<'a>(&'a self, conn: &'a Connection) -> AfterHandshakeOutcome {
        let id = conn.remote_id();
        if PUBLIC_ALPNS.contains(&conn.alpn()) || self.0.is_allowed(&id) {
            AfterHandshakeOutcome::accept()
        } else {
            tracing::debug!(peer = %id.fmt_short(), "rejected untrusted peer");
            AfterHandshakeOutcome::Reject {
                error_code: VarInt::from_u32(403),
                reason: b"not trusted".to_vec(),
            }
        }
    }
}
