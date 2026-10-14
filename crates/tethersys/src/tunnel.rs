//! Device-level tunnels through a WireGuard hub on the server.
//!
//! The in-app transports cover your own app's traffic. A tunnel covers everything else:
//! legacy apps, SMB, RDP, games, or a phone that must look like it is on the home LAN. The
//! device generates its WireGuard key locally (the private key never leaves it), leases an
//! address from the server over the authenticated tethersys channel, and gets back a standard
//! WireGuard config. Hand that config to the platform tunnel API (wireguard-android,
//! WireGuardKit on iOS, wireguard-nt or the WireGuard service on Windows).

use anyhow::{Result, bail};
use curve25519_dalek::montgomery::MontgomeryPoint;
use data_encoding::BASE64;
use serde::{Deserialize, Serialize};

use crate::{
    identity::NodeId,
    node::Inner,
    svc::{SvcReq, SvcResp, WgLease},
    wire::random_bytes,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct WgKeypair {
    pub private: String,
    pub public: String,
}

impl std::fmt::Debug for WgKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgKeypair")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl WgKeypair {
    pub fn generate() -> Self {
        let mut sk = random_bytes::<32>();
        // WireGuard clamps on use, but clamping here keeps the stored key canonical.
        sk[0] &= 248;
        sk[31] &= 127;
        sk[31] |= 64;
        let pk = MontgomeryPoint::mul_base_clamped(sk).to_bytes();
        Self {
            private: BASE64.encode(&sk),
            public: BASE64.encode(&pk),
        }
    }
}

/// A leased tunnel plus the matching client config.
#[derive(Debug, Clone)]
pub struct Tunnel {
    pub lease: WgLease,
    pub keys: WgKeypair,
}

impl Tunnel {
    /// Standard `wg-quick` config. Every WireGuard client can import it.
    pub fn wg_quick_config(&self) -> String {
        format!(
            "[Interface]\nPrivateKey = {}\nAddress = {}\n\n[Peer]\nPublicKey = {}\nEndpoint = {}\nAllowedIPs = {}\nPersistentKeepalive = 25\n",
            self.keys.private,
            self.lease.address,
            self.lease.server_pub,
            self.lease.endpoint,
            self.lease.allowed_ips
        )
    }
}

impl Inner {
    pub(crate) async fn lease_tunnel(&self, keys: Option<WgKeypair>) -> Result<Tunnel> {
        let keys = keys.unwrap_or_else(WgKeypair::generate);
        match self
            .svc(SvcReq::WgLease {
                wg_pub: keys.public.clone(),
            })
            .await?
        {
            SvcResp::Lease(lease) => Ok(Tunnel { lease, keys }),
            _ => bail!("server does not offer tunnels"),
        }
    }

    pub(crate) async fn release_tunnel(&self) -> Result<()> {
        self.svc(SvcReq::WgRelease).await.map(|_| ())
    }

    /// Tunnel addresses of other members, to reach them by IP inside the tunnel.
    pub(crate) async fn tunnel_peers(&self) -> Result<Vec<(NodeId, String)>> {
        match self.svc(SvcReq::WgPeers).await? {
            SvcResp::WgPeers(p) => Ok(p),
            _ => bail!("server does not offer tunnels"),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn key_and_config_shape() {
        let k = super::WgKeypair::generate();
        assert_eq!(k.private.len(), 44);
        assert_eq!(k.public.len(), 44);
        assert!(
            !format!("{k:?}").contains(&k.private),
            "debug must not leak the key"
        );
    }
}
