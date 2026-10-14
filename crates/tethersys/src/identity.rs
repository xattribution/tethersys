//! Device identity.
//!
//! A node is its Ed25519 key. The public half is the node's address on the network
//! (`NodeId`), and the TLS handshake proves possession of the private half, so a
//! connection to a `NodeId` can only ever reach that device.
//!
//! A second X25519 "box" key is derived from the identity in a separate domain. It is
//! only used to seal mailbox envelopes, so the signing key is never reused for
//! Diffie-Hellman.

use std::path::Path;

use anyhow::{Context, Result};
use curve25519_dalek::montgomery::MontgomeryPoint;
use iroh::SecretKey;

pub type NodeId = iroh::EndpointId;

/// Load the identity stored at `path`, or create and store a new one.
pub fn load_or_create(path: &Path) -> Result<SecretKey> {
    if let Ok(bytes) = std::fs::read(path) {
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .context("identity file is not 32 bytes")?;
        return Ok(SecretKey::from_bytes(&arr));
    }
    let key = SecretKey::generate();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    write_private(path, &key.to_bytes())?;
    Ok(key)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// X25519 key used only for sealing mailbox envelopes.
#[derive(Clone)]
pub struct BoxKey {
    secret: [u8; 32],
    pub public: [u8; 32],
}

impl BoxKey {
    pub fn derive(identity: &SecretKey) -> Self {
        let secret = blake3::derive_key("tethersys box key v1", &identity.to_bytes());
        let public = MontgomeryPoint::mul_base_clamped(secret).to_bytes();
        Self { secret, public }
    }

    pub(crate) fn dh(&self, their_public: &[u8; 32]) -> [u8; 32] {
        MontgomeryPoint(*their_public)
            .mul_clamped(self.secret)
            .to_bytes()
    }
}
