//! One event stream for everything the app may want to react to.

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::identity::NodeId;

/// How bytes are currently reaching a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkKind {
    /// Straight UDP between the two devices (same LAN or hole-punched).
    Direct,
    /// Forwarded by a relay. Still end-to-end encrypted; the relay sees only ciphertext.
    Relayed,
    /// Peer was unreachable; the payload went to the server mailbox.
    Queued,
}

#[derive(Debug, Clone)]
pub enum Event {
    /// A connection to a peer came up.
    Connected {
        peer: NodeId,
        link: LinkKind,
    },
    /// The best path to a peer changed (for example relay -> direct after a hole punch).
    LinkChanged {
        peer: NodeId,
        link: LinkKind,
        rtt_ms: u64,
    },
    /// A pairing completed in either direction.
    Paired {
        peer: NodeId,
        name: String,
    },
    /// A direct message, or one delivered later from the mailbox.
    Message {
        from: NodeId,
        channel: String,
        body: Bytes,
        from_mailbox: bool,
    },
    /// A peer offered a file.
    FileOffered(crate::files::FileOffer),
    FileProgress {
        hash: String,
        bytes: u64,
        total: u64,
    },
    FileDone {
        hash: String,
        path: std::path::PathBuf,
    },
    FileFailed {
        hash: String,
        error: String,
    },
    /// A verified message on a pub/sub topic.
    TopicMessage {
        topic: String,
        author: NodeId,
        body: Bytes,
    },
    /// A sync space changed because of a local or remote write.
    SpaceChanged {
        space: String,
        key: String,
        author: NodeId,
        deleted: bool,
    },
    /// Status of the optional server changed.
    Server {
        connected: bool,
        detail: String,
    },
}
