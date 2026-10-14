//! Pairing: turning a stranger's key into a trusted peer.
//!
//! The host creates an [`Invite`] (a short string, easy to put in a QR code or link). It
//! carries the host's full address and a one-time secret. The joiner dials the host by
//! key, so TLS proves it reached the real host, then presents the secret. The host checks
//! it in constant time, and both sides pin each other. Nobody without the invite can
//! pair, and a copied invite stops working once its uses run out or it expires.

use std::{collections::HashMap, sync::Mutex, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use data_encoding::BASE32_NOPAD;
use iroh::{
    EndpointAddr,
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler},
};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::{
    events::Event,
    identity::NodeId,
    node::Inner,
    trust::Peer,
    wire::{now_ms, random_bytes, read_frame, write_frame},
};

pub const ALPN: &[u8] = b"tethersys/pair/1";
const PREFIX: &str = "tethersys1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Invite {
    pub addr: EndpointAddr,
    pub secret: [u8; 16],
    pub expires_ms: u64,
    pub host_name: String,
}

impl Invite {
    pub fn encode(&self) -> String {
        let bytes = postcard::to_stdvec(self).expect("invite encodes");
        format!("{PREFIX}{}", BASE32_NOPAD.encode(&bytes).to_lowercase())
    }

    pub fn decode(s: &str) -> Result<Self> {
        let body = s
            .trim()
            .strip_prefix(PREFIX)
            .ok_or_else(|| anyhow!("not a tethersys invite"))?;
        let bytes = BASE32_NOPAD
            .decode(body.to_uppercase().as_bytes())
            .context("invite is not valid base32")?;
        postcard::from_bytes(&bytes).context("invite is corrupt")
    }

    pub fn host(&self) -> NodeId {
        self.addr.id
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Pending {
    expires_ms: u64,
    uses_left: u32,
    tags: Vec<String>,
}

#[derive(Debug, Default)]
pub(crate) struct Invites(Mutex<HashMap<[u8; 16], Pending>>);

impl Invites {
    pub fn add(&self, secret: [u8; 16], ttl: Duration, uses: u32, tags: Vec<String>) -> u64 {
        let expires_ms = now_ms() + ttl.as_millis() as u64;
        self.0.lock().unwrap().insert(
            secret,
            Pending {
                expires_ms,
                uses_left: uses.max(1),
                tags,
            },
        );
        expires_ms
    }

    /// Consume one use of a secret. Returns the tags to apply to the new peer.
    fn redeem(&self, presented: &[u8; 16]) -> Option<Vec<String>> {
        let now = now_ms();
        let mut map = self.0.lock().unwrap();
        map.retain(|_, p| p.expires_ms > now && p.uses_left > 0);
        // Compare against every live secret in constant time so timing leaks nothing.
        let hit = map
            .keys()
            .copied()
            .find(|k| bool::from(k.ct_eq(presented)))?;
        let entry = map.get_mut(&hit)?;
        entry.uses_left -= 1;
        let tags = entry.tags.clone();
        if entry.uses_left == 0 {
            map.remove(&hit);
        }
        Some(tags)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct PairRequest {
    secret: [u8; 16],
    name: String,
    box_pub: [u8; 32],
    addr: EndpointAddr,
}

#[derive(Debug, Serialize, Deserialize)]
enum PairResponse {
    Ok { name: String, box_pub: [u8; 32] },
    Denied,
}

#[derive(Debug, Clone)]
pub(crate) struct PairingHandler(pub std::sync::Arc<Inner>);

impl ProtocolHandler for PairingHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let inner = &self.0;
        let peer = conn.remote_id();
        let (mut send, mut recv) = conn.accept_bi().await.map_err(AcceptError::from_err)?;
        let req: PairRequest = read_frame(&mut recv).await.map_err(boxed)?;
        let resp = match inner.invites.redeem(&req.secret) {
            Some(tags) => {
                let mut addr = req.addr;
                addr.id = peer; // never trust a self-reported id; TLS already told us who this is
                inner
                    .trust
                    .upsert(Peer {
                        id: peer,
                        name: req.name.clone(),
                        box_pub: Some(req.box_pub),
                        last_addr: Some(addr.clone()),
                        added_ms: 0,
                        tags,
                    })
                    .map_err(boxed)?;
                inner.memory.add_endpoint_info(addr);
                let _ = inner.events.send(Event::Paired {
                    peer,
                    name: req.name,
                });
                PairResponse::Ok {
                    name: inner.name.clone(),
                    box_pub: inner.box_key.public,
                }
            }
            None => PairResponse::Denied,
        };
        write_frame(&mut send, &resp).await.map_err(boxed)?;
        send.finish().map_err(AcceptError::from_err)?;
        let _ = send.stopped().await;
        Ok(())
    }
}

fn boxed(e: anyhow::Error) -> AcceptError {
    AcceptError::from_boxed(e.into())
}

impl Inner {
    pub(crate) fn create_invite(&self, ttl: Duration, uses: u32, tags: Vec<String>) -> Invite {
        let secret = random_bytes::<16>();
        let expires_ms = self.invites.add(secret, ttl, uses, tags);
        Invite {
            addr: self.ep.addr(),
            secret,
            expires_ms,
            host_name: self.name.clone(),
        }
    }

    pub(crate) async fn redeem_invite(&self, invite: &Invite) -> Result<Peer> {
        if invite.expires_ms < now_ms() {
            bail!("invite expired");
        }
        if invite.host() == self.ep.id() {
            bail!("this is our own invite");
        }
        let conn = tokio::time::timeout(
            self.cfg.connect_timeout,
            self.ep.connect(invite.addr.clone(), ALPN),
        )
        .await
        .context("timed out reaching the invite host")??;
        let req = PairRequest {
            secret: invite.secret,
            name: self.name.clone(),
            box_pub: self.box_key.public,
            addr: self.ep.addr(),
        };
        let resp: PairResponse = crate::wire::call(&conn, &req).await?;
        conn.close(0u32.into(), b"paired");
        match resp {
            PairResponse::Ok { name, box_pub } => {
                let peer = Peer {
                    id: invite.host(),
                    name: name.clone(),
                    box_pub: Some(box_pub),
                    last_addr: Some(invite.addr.clone()),
                    added_ms: 0,
                    tags: Vec::new(),
                };
                self.trust.upsert(peer.clone())?;
                self.memory.add_endpoint_info(invite.addr.clone());
                let _ = self.events.send(Event::Paired {
                    peer: invite.host(),
                    name,
                });
                Ok(self.trust.get(&peer.id).unwrap_or(peer))
            }
            PairResponse::Denied => bail!("invite was rejected (used up, expired or wrong)"),
        }
    }
}
