//! Pub/sub topics over iroh-gossip.
//!
//! Gossip forwards messages hop by hop, so the peer that delivered a message is often not
//! the one who wrote it. Every message is therefore signed by its author and verified on
//! arrival; forged or altered messages are dropped before the app sees them.

use std::sync::Arc;

use anyhow::{Result, anyhow};
use bytes::Bytes;
use iroh::Signature;
use iroh_gossip::{
    TopicId,
    api::{Event as GossipEvent, GossipSender},
};
use n0_future::StreamExt;
use serde::{Deserialize, Serialize};

use crate::{
    events::Event,
    identity::NodeId,
    node::Inner,
    trust::TrustMode,
    wire::{now_ms, random_bytes},
};

pub fn topic_id(name: &str) -> TopicId {
    TopicId::from_bytes(blake3::derive_key("tethersys topic id v1", name.as_bytes()))
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Signed {
    pub author: NodeId,
    pub ts_ms: u64,
    pub nonce: [u8; 8],
    pub body: Vec<u8>,
    pub sig: Vec<u8>,
}

fn sig_input(topic: &TopicId, ts_ms: u64, nonce: &[u8; 8], body: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("tethersys topic message v1");
    h.update(topic.as_bytes());
    h.update(&ts_ms.to_be_bytes());
    h.update(nonce);
    h.update(body);
    *h.finalize().as_bytes()
}

pub(crate) fn sign(key: &iroh::SecretKey, topic: &TopicId, body: &[u8]) -> Vec<u8> {
    let ts_ms = now_ms();
    let nonce = random_bytes::<8>();
    let sig = key.sign(&sig_input(topic, ts_ms, &nonce, body));
    postcard::to_stdvec(&Signed {
        author: key.public(),
        ts_ms,
        nonce,
        body: body.to_vec(),
        sig: sig.to_bytes().to_vec(),
    })
    .expect("encodes")
}

pub(crate) fn verify(topic: &TopicId, raw: &[u8]) -> Option<(NodeId, Vec<u8>)> {
    let s: Signed = postcard::from_bytes(raw).ok()?;
    let sig: [u8; 64] = s.sig.as_slice().try_into().ok()?;
    s.author
        .verify(
            &sig_input(topic, s.ts_ms, &s.nonce, &s.body),
            &Signature::from_bytes(&sig),
        )
        .ok()?;
    Some((s.author, s.body))
}

/// A joined topic. Incoming messages arrive as [`Event::TopicMessage`].
#[derive(Debug, Clone)]
pub struct Topic {
    name: String,
    id: TopicId,
    sender: GossipSender,
    inner: Arc<Inner>,
}

impl Topic {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub async fn publish(&self, body: impl Into<Bytes>) -> Result<()> {
        let body: Bytes = body.into();
        let raw = sign(self.inner.ep.secret_key(), &self.id, &body);
        self.sender
            .broadcast(raw.into())
            .await
            .map_err(|e| anyhow!("broadcast: {e}"))
    }

    /// Add more peers to the topic swarm, for example ones that just came online.
    pub async fn add_peers(&self, peers: Vec<NodeId>) -> Result<()> {
        for p in &peers {
            self.inner.prime_addr(*p).await;
        }
        self.sender
            .join_peers(peers)
            .await
            .map_err(|e| anyhow!("join: {e}"))
    }
}

impl Inner {
    pub(crate) async fn join_topic(
        self: &Arc<Self>,
        name: &str,
        bootstrap: Option<Vec<NodeId>>,
    ) -> Result<Topic> {
        let id = topic_id(name);
        let bootstrap =
            bootstrap.unwrap_or_else(|| self.trust.list().into_iter().map(|p| p.id).collect());
        for p in &bootstrap {
            self.prime_addr(*p).await;
        }
        let (sender, mut receiver) = self
            .gossip
            .subscribe(id, bootstrap)
            .await
            .map_err(|e| anyhow!("subscribe: {e}"))?
            .split();

        let inner = self.clone();
        let topic_name = name.to_string();
        tokio::spawn(async move {
            while let Some(ev) = receiver.next().await {
                let Ok(GossipEvent::Received(msg)) = ev else {
                    continue;
                };
                let Some((author, body)) = verify(&id, &msg.content) else {
                    tracing::debug!("dropped unsigned or forged topic message");
                    continue;
                };
                if inner.trust.mode() == TrustMode::Pinned && !inner.trust.is_peer(&author) {
                    continue;
                }
                inner.on_topic_message(&topic_name, author, body);
            }
        });
        Ok(Topic {
            name: name.to_string(),
            id,
            sender,
            inner: self.clone(),
        })
    }

    fn on_topic_message(&self, topic: &str, author: NodeId, body: Vec<u8>) {
        #[cfg(feature = "sync")]
        if let Some(space) = topic.strip_prefix(crate::sync::TOPIC_PREFIX) {
            self.on_space_broadcast(space, author, &body);
            return;
        }
        let _ = self.events.send(Event::TopicMessage {
            topic: topic.to_string(),
            author,
            body: Bytes::from(body),
        });
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn forged_messages_fail() {
        let k = iroh::SecretKey::generate();
        let t = super::topic_id("chat");
        let raw = super::sign(&k, &t, b"hi");
        assert_eq!(
            super::verify(&t, &raw).unwrap(),
            (k.public(), b"hi".to_vec())
        );
        // Same bytes replayed into another topic do not verify.
        assert!(super::verify(&super::topic_id("other"), &raw).is_none());
    }
}
