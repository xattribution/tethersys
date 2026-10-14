//! Replicated key-value spaces (last-writer-wins).
//!
//! A space is a small map that every member keeps a full copy of. Writes are signed by
//! their author, broadcast live over a gossip topic, and reconciled by a digest exchange
//! whenever two members meet, so a device that was offline for a week catches up on its
//! next contact. Values are opaque bytes: store JSON, or CRDT updates (Automerge, Yjs)
//! when an app needs merge semantics richer than last-writer-wins.
//!
//! Sized for app state (settings, presence, rosters, indexes), up to tens of thousands of
//! keys. Bulk data belongs in files, with the hash stored here.

use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Result, anyhow, bail};
use bytes::Bytes;
use iroh::{
    Signature,
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler},
};
use serde::{Deserialize, Serialize};

use crate::{
    events::Event,
    identity::NodeId,
    node::Inner,
    pubsub::Topic,
    trust::TrustMode,
    wire::{now_ms, read_frame, write_frame},
};

pub const ALPN: &[u8] = b"tethersys/sync/1";
pub(crate) const TOPIC_PREFIX: &str = "tethersys.space/";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    pub key: String,
    /// `None` is a deletion marker, kept so the delete propagates.
    pub value: Option<Vec<u8>>,
    pub ts: u64,
    pub author: NodeId,
    sig: Vec<u8>,
}

impl Entry {
    fn sig_input(space: &str, key: &str, value: &Option<Vec<u8>>, ts: u64) -> [u8; 32] {
        let mut h = blake3::Hasher::new_derive_key("tethersys space entry v1");
        for part in [space.as_bytes(), key.as_bytes()] {
            h.update(&(part.len() as u64).to_be_bytes());
            h.update(part);
        }
        match value {
            Some(v) => {
                h.update(&[1]);
                h.update(v);
            }
            None => {
                h.update(&[0]);
            }
        }
        h.update(&ts.to_be_bytes());
        *h.finalize().as_bytes()
    }

    fn new(key: &iroh::SecretKey, space: &str, k: &str, value: Option<Vec<u8>>, ts: u64) -> Self {
        let sig = key.sign(&Self::sig_input(space, k, &value, ts));
        Self {
            key: k.to_string(),
            value,
            ts,
            author: key.public(),
            sig: sig.to_bytes().to_vec(),
        }
    }

    fn verify(&self, space: &str) -> bool {
        let Ok(sig) = <[u8; 64]>::try_from(self.sig.as_slice()) else {
            return false;
        };
        self.author
            .verify(
                &Self::sig_input(space, &self.key, &self.value, self.ts),
                &Signature::from_bytes(&sig),
            )
            .is_ok()
    }

    /// Total order for conflict resolution: newer timestamp wins, author key breaks ties.
    fn beats(&self, other: &Entry) -> bool {
        (self.ts, self.author.as_bytes()) > (other.ts, other.author.as_bytes())
    }
}

#[derive(Debug)]
pub(crate) struct SpaceState {
    name: String,
    path: Option<PathBuf>,
    map: Mutex<BTreeMap<String, Entry>>,
    /// When set, only these peers' writes are accepted and only they are synced with.
    members: Option<Vec<NodeId>>,
}

impl SpaceState {
    fn load(name: &str, dir: Option<&PathBuf>, members: Option<Vec<NodeId>>) -> Self {
        let path = dir.map(|d| {
            d.join("spaces")
                .join(format!("{}.bin", blake3::hash(name.as_bytes()).to_hex()))
        });
        let mut map = BTreeMap::new();
        if let Some(p) = &path
            && let Ok(bytes) = std::fs::read(p)
            && let Ok(entries) = postcard::from_bytes::<Vec<Entry>>(&bytes)
        {
            for e in entries {
                map.insert(e.key.clone(), e);
            }
        }
        Self {
            name: name.to_string(),
            path,
            map: Mutex::new(map),
            members,
        }
    }

    fn save(&self, map: &BTreeMap<String, Entry>) {
        let Some(p) = &self.path else { return };
        let entries: Vec<&Entry> = map.values().collect();
        let result = (|| -> Result<()> {
            std::fs::create_dir_all(p.parent().unwrap())?;
            let tmp = p.with_extension("tmp");
            std::fs::write(&tmp, postcard::to_stdvec(&entries)?)?;
            std::fs::rename(tmp, p)?;
            Ok(())
        })();
        if let Err(e) = result {
            tracing::warn!("could not persist space {}: {e:#}", self.name);
        }
    }

    fn next_ts(&self) -> u64 {
        let map = self.map.lock().unwrap();
        let last = map.values().map(|e| e.ts).max().unwrap_or(0);
        now_ms().max(last + 1)
    }

    /// Merge entries; returns the ones that changed local state.
    fn merge(&self, incoming: Vec<Entry>) -> Vec<Entry> {
        let mut changed = Vec::new();
        let mut map = self.map.lock().unwrap();
        for e in incoming {
            let wins = map.get(&e.key).is_none_or(|cur| e.beats(cur));
            if wins {
                map.insert(e.key.clone(), e.clone());
                changed.push(e);
            }
        }
        if !changed.is_empty() {
            self.save(&map);
        }
        changed
    }

    fn digest(&self) -> Vec<(String, u64, NodeId)> {
        let map = self.map.lock().unwrap();
        map.values()
            .map(|e| (e.key.clone(), e.ts, e.author))
            .collect()
    }
}

/// Handle to an open space.
#[derive(Debug, Clone)]
pub struct Space {
    state: Arc<SpaceState>,
    inner: Arc<Inner>,
    topic: Topic,
}

impl Space {
    pub fn name(&self) -> &str {
        &self.state.name
    }

    pub fn get(&self, key: &str) -> Option<Bytes> {
        let map = self.state.map.lock().unwrap();
        map.get(key)?.value.clone().map(Bytes::from)
    }

    /// Live entries in key order.
    pub fn entries(&self) -> Vec<(String, Bytes)> {
        let map = self.state.map.lock().unwrap();
        map.values()
            .filter_map(|e| Some((e.key.clone(), Bytes::from(e.value.clone()?))))
            .collect()
    }

    pub async fn set(&self, key: &str, value: impl Into<Bytes>) -> Result<()> {
        self.write(key, Some(value.into().to_vec())).await
    }

    pub async fn delete(&self, key: &str) -> Result<()> {
        self.write(key, None).await
    }

    async fn write(&self, key: &str, value: Option<Vec<u8>>) -> Result<()> {
        let ts = self.state.next_ts();
        let entry = Entry::new(self.inner.ep.secret_key(), &self.state.name, key, value, ts);
        for e in self.state.merge(vec![entry.clone()]) {
            self.inner.emit_space_change(&self.state.name, &e);
        }
        // Live peers get it now; everyone else catches up on the next reconcile.
        let _ = self.topic.publish(postcard::to_stdvec(&entry)?).await;
        Ok(())
    }

    /// Reconcile with one peer right now. Returns how many entries changed locally.
    pub async fn sync_with(&self, peer: NodeId) -> Result<usize> {
        self.inner.reconcile(&self.state, peer).await
    }

    /// Reconcile with every member that is reachable.
    pub async fn sync_now(&self) -> usize {
        let mut total = 0;
        for peer in self.inner.space_peers(&self.state) {
            total += self.sync_with(peer).await.unwrap_or(0);
        }
        total
    }
}

#[derive(Debug, Serialize, Deserialize)]
enum SyncReq {
    Hello {
        space: String,
        have: Vec<(String, u64, NodeId)>,
    },
    Push {
        space: String,
        entries: Vec<Entry>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
enum SyncResp {
    Diff {
        entries: Vec<Entry>,
        want: Vec<String>,
    },
    Ok,
    Error(String),
}

#[derive(Debug, Clone)]
pub(crate) struct SyncHandler(pub Arc<Inner>);

impl ProtocolHandler for SyncHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let peer = conn.remote_id();
        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
            let resp = match read_frame::<SyncReq>(&mut recv).await {
                Ok(req) => self.0.answer_sync(peer, req),
                Err(e) => SyncResp::Error(e.to_string()),
            };
            let _ = write_frame(&mut send, &resp).await;
            let _ = send.finish();
        }
        Ok(())
    }
}

impl Inner {
    pub(crate) async fn open_space(
        self: &Arc<Self>,
        name: &str,
        members: Option<Vec<NodeId>>,
    ) -> Result<Space> {
        let state = {
            let mut spaces = self.spaces.lock().unwrap();
            spaces
                .entry(name.to_string())
                .or_insert_with(|| {
                    Arc::new(SpaceState::load(
                        name,
                        self.cfg.data_dir.as_ref(),
                        members.clone(),
                    ))
                })
                .clone()
        };
        let topic = self
            .join_topic(&format!("{TOPIC_PREFIX}{name}"), members.clone())
            .await?;
        let space = Space {
            state: state.clone(),
            inner: self.clone(),
            topic,
        };
        // Catch up now, then keep reconciling in the background.
        let bg = space.clone();
        let every = self.cfg.sync_interval;
        tokio::spawn(async move {
            loop {
                bg.sync_now().await;
                tokio::time::sleep(every).await;
                if Arc::strong_count(&bg.state) <= 2 {
                    break; // only this task and the registry still hold it
                }
            }
        });
        Ok(space)
    }

    fn space_peers(&self, state: &SpaceState) -> Vec<NodeId> {
        match &state.members {
            Some(m) => m.clone(),
            None => self.trust.list().into_iter().map(|p| p.id).collect(),
        }
    }

    fn may_write(&self, state: &SpaceState, author: &NodeId) -> bool {
        if *author == self.ep.id() {
            return true;
        }
        match &state.members {
            Some(m) => m.contains(author),
            None => self.trust.mode() == TrustMode::Open || self.trust.is_peer(author),
        }
    }

    fn accept_entries(&self, state: &SpaceState, entries: Vec<Entry>) -> usize {
        let ok: Vec<Entry> = entries
            .into_iter()
            .filter(|e| e.verify(&state.name) && self.may_write(state, &e.author))
            .collect();
        let changed = state.merge(ok);
        for e in &changed {
            self.emit_space_change(&state.name, e);
        }
        changed.len()
    }

    fn emit_space_change(&self, space: &str, e: &Entry) {
        let _ = self.events.send(Event::SpaceChanged {
            space: space.to_string(),
            key: e.key.clone(),
            author: e.author,
            deleted: e.value.is_none(),
        });
    }

    pub(crate) fn on_space_broadcast(&self, space: &str, _from: NodeId, body: &[u8]) {
        let Some(state) = self.spaces.lock().unwrap().get(space).cloned() else {
            return;
        };
        if let Ok(entry) = postcard::from_bytes::<Entry>(body) {
            self.accept_entries(&state, vec![entry]);
        }
    }

    fn answer_sync(&self, peer: NodeId, req: SyncReq) -> SyncResp {
        let space = match &req {
            SyncReq::Hello { space, .. } | SyncReq::Push { space, .. } => space.clone(),
        };
        let Some(state) = self.spaces.lock().unwrap().get(&space).cloned() else {
            return SyncResp::Error("space not open here".into());
        };
        if !self.space_peers(&state).contains(&peer) {
            return SyncResp::Error("not a member of this space".into());
        }
        match req {
            SyncReq::Hello { have, .. } => {
                let theirs: HashMap<String, (u64, NodeId)> =
                    have.into_iter().map(|(k, ts, a)| (k, (ts, a))).collect();
                let map = state.map.lock().unwrap();
                let mut entries = Vec::new();
                for e in map.values() {
                    let newer = theirs
                        .get(&e.key)
                        .is_none_or(|(ts, a)| (e.ts, e.author.as_bytes()) > (*ts, a.as_bytes()));
                    if newer {
                        entries.push(e.clone());
                    }
                }
                let want = theirs
                    .iter()
                    .filter(|(k, (ts, a))| {
                        map.get(*k)
                            .is_none_or(|e| (*ts, a.as_bytes()) > (e.ts, e.author.as_bytes()))
                    })
                    .map(|(k, _)| k.clone())
                    .collect();
                SyncResp::Diff { entries, want }
            }
            SyncReq::Push { entries, .. } => {
                self.accept_entries(&state, entries);
                SyncResp::Ok
            }
        }
    }

    async fn reconcile(&self, state: &SpaceState, peer: NodeId) -> Result<usize> {
        if peer == self.ep.id() {
            return Ok(0);
        }
        let conn = self.connect(peer, ALPN).await?;
        let hello = SyncReq::Hello {
            space: state.name.clone(),
            have: state.digest(),
        };
        let SyncResp::Diff { entries, want } = crate::wire::call(&conn, &hello).await? else {
            bail!("peer refused sync");
        };
        let changed = self.accept_entries(state, entries);
        if !want.is_empty() {
            let entries: Vec<Entry> = {
                let map = state.map.lock().unwrap();
                want.iter().filter_map(|k| map.get(k).cloned()).collect()
            };
            let push = SyncReq::Push {
                space: state.name.clone(),
                entries,
            };
            match crate::wire::call::<_, SyncResp>(&conn, &push).await? {
                SyncResp::Ok => {}
                SyncResp::Error(e) => return Err(anyhow!("push rejected: {e}")),
                SyncResp::Diff { .. } => bail!("unexpected reply"),
            }
        }
        Ok(changed)
    }
}

pub(crate) fn default_interval() -> Duration {
    Duration::from_secs(60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lww_and_signatures() {
        let a = iroh::SecretKey::generate();
        let s = SpaceState::load("t", None, None);
        let e1 = Entry::new(&a, "t", "k", Some(b"1".to_vec()), 10);
        let e2 = Entry::new(&a, "t", "k", Some(b"2".to_vec()), 20);
        assert_eq!(s.merge(vec![e2.clone()]).len(), 1);
        assert!(s.merge(vec![e1]).is_empty(), "older write must lose");
        assert!(e2.verify("t"));
        assert!(!e2.verify("other-space"), "entry is bound to its space");
        let mut forged = e2.clone();
        forged.value = Some(b"evil".to_vec());
        assert!(!forged.verify("t"));
    }
}
