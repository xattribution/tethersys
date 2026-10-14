//! Persistent server state: members, sealed mail, tunnel leases.
//!
//! Kept in one small file written atomically after each change. A server for a household,
//! a team or a fleet of a few thousand devices fits comfortably.

use std::{
    collections::{BTreeMap, VecDeque},
    path::PathBuf,
    sync::Mutex,
};

use anyhow::Result;
use iroh::{EndpointAddr, EndpointId};
use serde::{Deserialize, Serialize};
use tether::svc::MailItem;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Member {
    pub name: String,
    pub addr: Option<EndpointAddr>,
    pub last_seen_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMail {
    pub item: MailItem,
    pub from: EndpointId,
    pub stored_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    pub wg_pub: String,
    pub ip: [u8; 4],
    pub expires_ms: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Data {
    pub members: BTreeMap<EndpointId, Member>,
    pub mail: BTreeMap<EndpointId, VecDeque<StoredMail>>,
    pub leases: BTreeMap<EndpointId, Lease>,
}

pub struct State {
    path: PathBuf,
    pub data: Mutex<Data>,
}

impl State {
    pub fn load(path: PathBuf) -> Result<Self> {
        let data = match std::fs::read(&path) {
            Ok(b) => postcard::from_bytes(&b)?,
            Err(_) => Data::default(),
        };
        Ok(Self {
            path,
            data: Mutex::new(data),
        })
    }

    /// Run `f` on the data and persist the result.
    pub fn update<T>(&self, f: impl FnOnce(&mut Data) -> T) -> Result<T> {
        let mut d = self.data.lock().unwrap();
        let out = f(&mut d);
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, postcard::to_stdvec(&*d)?)?;
        std::fs::rename(tmp, &self.path)?;
        Ok(out)
    }

    pub fn is_member(&self, id: &EndpointId) -> bool {
        self.data.lock().unwrap().members.contains_key(id)
    }
}
