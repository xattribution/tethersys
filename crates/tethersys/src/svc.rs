//! Wire protocol between nodes and the optional `tethersysd` server.
//!
//! The server is just another iroh endpoint. Every request arrives on an authenticated
//! connection, so the server always knows which key is asking: a node can only fetch its
//! own mailbox and only lease a tunnel address for itself.

use anyhow::{Context, Result, anyhow};
use data_encoding::BASE32_NOPAD;
use iroh::{EndpointAddr, RelayUrl};
use serde::{Deserialize, Serialize};

use crate::identity::NodeId;

pub const ALPN: &[u8] = b"tethersys/svc/1";
const TICKET_PREFIX: &str = "tethersyssrv1";

/// Everything a node needs to use a server, in one pasteable string.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerTicket {
    pub addr: EndpointAddr,
    /// The server's own relay, if it runs one.
    pub relay: Option<RelayUrl>,
    /// Network join token. Also the relay's access token.
    pub token: String,
}

impl ServerTicket {
    pub fn encode(&self) -> String {
        let bytes = postcard::to_stdvec(self).expect("ticket encodes");
        format!(
            "{TICKET_PREFIX}{}",
            BASE32_NOPAD.encode(&bytes).to_lowercase()
        )
    }

    pub fn decode(s: &str) -> Result<Self> {
        let body = s
            .trim()
            .strip_prefix(TICKET_PREFIX)
            .ok_or_else(|| anyhow!("not a tethersys server ticket"))?;
        let bytes = BASE32_NOPAD
            .decode(body.to_uppercase().as_bytes())
            .context("ticket is not valid base32")?;
        postcard::from_bytes(&bytes).context("ticket is corrupt")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SvcReq {
    /// Join the network (first time) and publish our current address.
    Register {
        token: String,
        addr: EndpointAddr,
        name: String,
    },
    /// Latest address a member registered.
    Lookup {
        id: NodeId,
    },
    /// Store a sealed envelope for an offline member.
    MailPut {
        to: NodeId,
        envelope: Vec<u8>,
    },
    /// Fetch our queued envelopes. They stay until acknowledged.
    MailFetch,
    MailAck {
        ids: Vec<[u8; 16]>,
    },
    /// Ask the server to pull and hold a blob from us so offline peers can get it later.
    PinBlob {
        hash: String,
    },
    /// Lease a WireGuard address on the server's hub interface.
    WgLease {
        wg_pub: String,
    },
    WgRelease,
    /// Tunnel addresses of other members that currently hold leases.
    WgPeers,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SvcResp {
    Ok,
    Addr(Option<EndpointAddr>),
    Mail(Vec<MailItem>),
    Lease(WgLease),
    WgPeers(Vec<(NodeId, String)>),
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailItem {
    pub id: [u8; 16],
    pub envelope: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WgLease {
    /// Address assigned to this device, e.g. "10.77.0.5/32".
    pub address: String,
    /// The server's WireGuard public key (base64).
    pub server_pub: String,
    /// "host:port" the device should send WireGuard packets to.
    pub endpoint: String,
    /// Subnet routed through the tunnel, e.g. "10.77.0.0/24".
    pub allowed_ips: String,
    pub expires_ms: u64,
}

impl SvcResp {
    pub fn into_result(self) -> Result<Self> {
        match self {
            SvcResp::Error(e) => Err(anyhow!("server: {e}")),
            other => Ok(other),
        }
    }
}
