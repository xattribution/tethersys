//! Store-and-forward for peers that are offline.
//!
//! Envelopes are sealed to the recipient's box key with an ephemeral X25519 exchange and
//! ChaCha20-Poly1305, and the inner message is signed by the sender's identity key. The
//! server stores opaque bytes: it learns who a message is for, but cannot read it, forge
//! it, or change who it claims to be from.

use anyhow::{Context, Result, anyhow, bail};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use curve25519_dalek::montgomery::MontgomeryPoint;
use iroh::Signature;
use serde::{Deserialize, Serialize};

use crate::{
    identity::{BoxKey, NodeId},
    messaging::MsgReq,
    node::Inner,
    svc::{SvcReq, SvcResp},
    wire::random_bytes,
};

#[derive(Serialize, Deserialize)]
struct Sealed {
    eph_pub: [u8; 32],
    nonce: [u8; 12],
    ct: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct Inside {
    from: NodeId,
    sig: Vec<u8>,
    msg: Vec<u8>,
}

fn sig_input(to: &NodeId, msg: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("tether mail signature v1");
    h.update(to.as_bytes());
    h.update(msg);
    *h.finalize().as_bytes()
}

fn aead_key(shared: &[u8; 32], eph_pub: &[u8; 32], recipient: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("tether mailbox v1");
    h.update(shared);
    h.update(eph_pub);
    h.update(recipient);
    *h.finalize().as_bytes()
}

pub(crate) fn seal(
    identity: &iroh::SecretKey,
    to: NodeId,
    to_box: &[u8; 32],
    msg: &MsgReq,
) -> Result<Vec<u8>> {
    let msg = postcard::to_stdvec(msg)?;
    let sig = identity.sign(&sig_input(&to, &msg));
    let inside = postcard::to_stdvec(&Inside {
        from: identity.public(),
        sig: sig.to_bytes().to_vec(),
        msg,
    })?;
    let eph = random_bytes::<32>();
    let eph_pub = MontgomeryPoint::mul_base_clamped(eph).to_bytes();
    let shared = MontgomeryPoint(*to_box).mul_clamped(eph).to_bytes();
    if shared == [0u8; 32] {
        bail!("recipient box key is invalid");
    }
    let cipher = ChaCha20Poly1305::new(&aead_key(&shared, &eph_pub, to_box).into());
    let nonce = random_bytes::<12>();
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &inside,
                aad: to.as_bytes(),
            },
        )
        .map_err(|_| anyhow!("seal failed"))?;
    Ok(postcard::to_stdvec(&Sealed { eph_pub, nonce, ct })?)
}

pub(crate) fn open(me: NodeId, my_box: &BoxKey, envelope: &[u8]) -> Result<(NodeId, MsgReq)> {
    let sealed: Sealed = postcard::from_bytes(envelope).context("bad envelope")?;
    let shared = my_box.dh(&sealed.eph_pub);
    let cipher = ChaCha20Poly1305::new(&aead_key(&shared, &sealed.eph_pub, &my_box.public).into());
    let inside = cipher
        .decrypt(
            Nonce::from_slice(&sealed.nonce),
            Payload {
                msg: &sealed.ct,
                aad: me.as_bytes(),
            },
        )
        .map_err(|_| anyhow!("envelope does not decrypt for this node"))?;
    let inside: Inside = postcard::from_bytes(&inside)?;
    let sig: [u8; 64] = inside.sig.as_slice().try_into().context("bad signature")?;
    inside
        .from
        .verify(&sig_input(&me, &inside.msg), &Signature::from_bytes(&sig))
        .map_err(|_| anyhow!("envelope signature is invalid"))?;
    Ok((inside.from, postcard::from_bytes(&inside.msg)?))
}

impl Inner {
    pub(crate) async fn mailbox_put(&self, to: NodeId, msg: &MsgReq) -> Result<()> {
        if self.server_id().is_none() {
            bail!("peer is offline and no server mailbox is configured");
        }
        let to_box = self
            .trust
            .get(&to)
            .and_then(|p| p.box_pub)
            .ok_or_else(|| anyhow!("no box key for {}; pair first", to.fmt_short()))?;
        let envelope = seal(self.ep.secret_key(), to, &to_box, msg)?;
        self.svc(SvcReq::MailPut { to, envelope }).await?;
        Ok(())
    }

    /// Pull, open and deliver everything waiting for us. Returns how many were delivered.
    pub(crate) async fn mailbox_drain(&self) -> Result<usize> {
        let SvcResp::Mail(items) = self.svc(SvcReq::MailFetch).await? else {
            bail!("unexpected server reply");
        };
        let mut ids = Vec::with_capacity(items.len());
        let mut delivered = 0;
        for item in items {
            ids.push(item.id);
            match open(self.ep.id(), &self.box_key, &item.envelope) {
                Ok((from, req)) if self.trust.is_peer(&from) => {
                    self.dispatch_from_mailbox(from, req).await;
                    delivered += 1;
                }
                Ok((from, _)) => tracing::warn!("dropped mail from untrusted {}", from.fmt_short()),
                Err(e) => tracing::warn!("dropped unreadable mail: {e:#}"),
            }
        }
        if !ids.is_empty() {
            self.svc(SvcReq::MailAck { ids }).await?;
        }
        Ok(delivered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg() -> MsgReq {
        MsgReq {
            id: [7; 16],
            channel: "chat".into(),
            body: b"hello".to_vec(),
            want_reply: false,
        }
    }

    #[test]
    fn round_trip_and_tamper() {
        let alice = iroh::SecretKey::generate();
        let bob = iroh::SecretKey::generate();
        let bob_box = BoxKey::derive(&bob);
        let env = seal(&alice, bob.public(), &bob_box.public, &msg()).unwrap();

        let (from, got) = open(bob.public(), &bob_box, &env).unwrap();
        assert_eq!(from, alice.public());
        assert_eq!(got.body, b"hello");

        // A third party cannot open it.
        let eve = iroh::SecretKey::generate();
        assert!(open(eve.public(), &BoxKey::derive(&eve), &env).is_err());

        // Flipping any ciphertext byte is detected.
        let mut bad = env.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(open(bob.public(), &bob_box, &bad).is_err());
    }
}
