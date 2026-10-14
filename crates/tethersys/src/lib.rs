//! # tethersys
//!
//! Layered peer-to-peer networking for apps. One [`Node`] gives you pairing, messaging,
//! request/response, file transfer, pub/sub, replicated state, an offline mailbox and
//! device tunnels. Every layer works with no server; an optional `tethersysd` server adds
//! reach and persistence without ever seeing plaintext.
//!
//! ```no_run
//! # async fn demo() -> anyhow::Result<()> {
//! use tethersys::{Config, Node, Profile};
//!
//! let node = Node::spawn(Config::new("laptop", Profile::Public).data_dir("./state")).await?;
//! let invite = node.invite(std::time::Duration::from_secs(600), 1).encode();
//! // ...show `invite` as a QR code; the other device calls `node.join(&invite)`.
//! let mut events = node.events();
//! while let Ok(ev) = events.recv().await {
//!     println!("{ev:?}");
//! }
//! # Ok(()) }
//! ```
//!
//! See `docs/ARCHITECTURE.md` for the layer model and `INTEGRATION.md` for adding it to an app.

pub mod events;
pub mod files;
pub mod forward;
pub mod identity;
mod mailbox;
pub mod messaging;
pub mod node;
pub mod pairing;
pub mod pubsub;
pub mod svc;
pub mod sync;
pub mod trust;
pub mod tunnel;
pub mod wire;

pub use bytes::Bytes;
pub use events::{Event, LinkKind};
pub use files::FileOffer;
pub use forward::{FORWARD_ALPN, Forward};
pub use identity::NodeId;
pub use iroh::{EndpointAddr, RelayUrl, SecretKey};
pub use messaging::Delivery;
pub use node::{Config, Discovery, Node, NodeBuilder, Profile, Relays};
pub use pairing::Invite;
pub use pubsub::Topic;
pub use svc::ServerTicket;
pub use sync::Space;
pub use trust::{Peer, TrustMode};
pub use tunnel::{Tunnel, WgKeypair};

/// Re-exported so apps can build custom protocols on the same endpoint.
pub use iroh;
pub use iroh_blobs;
