//! File transfer on top of iroh-blobs.
//!
//! Files are content-addressed by BLAKE3 hash and streamed with verified chunks, so a
//! transfer can resume after a drop, can pull from several providers at once, and a
//! corrupted or tampered chunk is rejected the moment it arrives.
//!
//! Sending is an offer message plus a pull: the sender imports the file and tells the
//! receiver its hash. If the receiver is offline, the optional server first pulls its own
//! copy, so the receiver can still fetch the file after the sender goes offline.

use serde::{Deserialize, Serialize};

use crate::identity::NodeId;

#[cfg_attr(not(feature = "files"), allow(dead_code))]
pub(crate) const OFFER_CHANNEL: &str = "tethersys.file.offer";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileOffer {
    pub from: NodeId,
    pub hash: String,
    pub name: String,
    pub size: u64,
    /// Nodes that hold the bytes. Usually the sender, plus the server when it pinned a copy.
    pub providers: Vec<NodeId>,
}

#[cfg(feature = "files")]
mod imp {
    use std::path::{Path, PathBuf};

    use anyhow::{Context, Result, bail};
    use bytes::Bytes;
    use iroh_blobs::{Hash, api::downloader::DownloadProgressItem};
    use n0_future::StreamExt;
    use serde::{Deserialize, Serialize};

    use super::{FileOffer, OFFER_CHANNEL};

    use crate::{
        events::{Event, LinkKind},
        identity::NodeId,
        messaging::Delivery,
        node::Inner,
    };

    #[derive(Debug, Serialize, Deserialize)]
    struct OfferBody {
        hash: String,
        name: String,
        size: u64,
        providers: Vec<NodeId>,
    }

    impl Inner {
        /// Import a file into the local store (hashing it once) and return its hash.
        pub(crate) async fn import_file(&self, path: &Path) -> Result<(Hash, u64)> {
            let abs = std::path::absolute(path)?;
            let size = tokio::fs::metadata(&abs).await?.len();
            let temp = match self.blobs.add_path(&abs).temp_tag().await {
                Ok(t) => t,
                Err(e) => bail!("import {}: {e}", abs.display()),
            };
            let hash = temp.hash();
            // One named tag per hash keeps every offered file alive until the app purges it.
            self.blobs
                .tags()
                .set(format!("tethersys-out/{hash}"), hash)
                .await?;
            Ok((hash, size))
        }

        pub(crate) async fn send_file(
            &self,
            to: NodeId,
            path: &Path,
            delivery: Delivery,
        ) -> Result<(FileOffer, LinkKind)> {
            let (hash, size) = self.import_file(path).await?;
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| hash.to_string());
            let me = self.ep.id();
            let mut body = OfferBody {
                hash: hash.to_string(),
                name,
                size,
                providers: vec![me],
            };

            // Try live first. Only pay for a server copy if the receiver is not reachable.
            if delivery != Delivery::Mailbox {
                let bytes = Bytes::from(postcard::to_stdvec(&body)?);
                match self
                    .send_message(to, OFFER_CHANNEL, bytes, Delivery::Direct)
                    .await
                {
                    Ok(link) => return Ok((self.offer_from(me, body), link)),
                    Err(e) if delivery == Delivery::Direct => return Err(e),
                    Err(e) => tracing::debug!("live file offer failed: {e:#}"),
                }
            }
            if let Some(server) = self.server_id() {
                self.pin_on_server(hash)
                    .await
                    .context("server could not keep a copy")?;
                body.providers.push(server);
            }
            let bytes = Bytes::from(postcard::to_stdvec(&body)?);
            let link = self
                .send_message(to, OFFER_CHANNEL, bytes, Delivery::Mailbox)
                .await?;
            Ok((self.offer_from(me, body), link))
        }

        fn offer_from(&self, from: NodeId, b: OfferBody) -> FileOffer {
            FileOffer {
                from,
                hash: b.hash,
                name: b.name,
                size: b.size,
                providers: b.providers,
            }
        }

        pub(crate) fn on_file_offer(&self, from: NodeId, body: &[u8]) {
            let Ok(b) = postcard::from_bytes::<OfferBody>(body) else {
                tracing::warn!("malformed file offer from {}", from.fmt_short());
                return;
            };
            let offer = self.offer_from(from, b);
            if let Some(dir) = self.cfg.auto_accept_files.clone() {
                let inner = self.self_arc();
                let offer = offer.clone();
                tokio::spawn(async move {
                    let dest = dir.join(sanitize(&offer.name));
                    let _ = inner.fetch_file(&offer, &dest).await;
                });
            }
            let _ = self.events.send(Event::FileOffered(offer));
        }

        /// Download an offered file and write it to `dest`. Resumes if partially fetched before.
        pub(crate) async fn fetch_file(&self, offer: &FileOffer, dest: &Path) -> Result<PathBuf> {
            let result = self.fetch_inner(offer, dest).await;
            match &result {
                Ok(p) => {
                    let _ = self.events.send(Event::FileDone {
                        hash: offer.hash.clone(),
                        path: p.clone(),
                    });
                }
                Err(e) => {
                    let _ = self.events.send(Event::FileFailed {
                        hash: offer.hash.clone(),
                        error: format!("{e:#}"),
                    });
                }
            }
            result
        }

        async fn fetch_inner(&self, offer: &FileOffer, dest: &Path) -> Result<PathBuf> {
            let hash: Hash = offer.hash.parse().context("bad hash in offer")?;
            // Seed addresses for every provider we already know, so the downloader can dial them.
            for p in &offer.providers {
                self.prime_addr(*p).await;
            }
            let downloader = self.blobs.downloader(&self.ep);
            let mut progress = downloader
                .download(hash, offer.providers.clone())
                .stream()
                .await?;
            let mut failed = false;
            // Report roughly every 1% so a big file does not flood the event channel.
            let step = (offer.size / 100).max(256 * 1024);
            let mut next_report = 0u64;
            while let Some(item) = progress.next().await {
                match item {
                    DownloadProgressItem::Progress(bytes) if bytes >= next_report => {
                        next_report = bytes + step;
                        let _ = self.events.send(Event::FileProgress {
                            hash: offer.hash.clone(),
                            bytes,
                            total: offer.size,
                        });
                    }
                    DownloadProgressItem::Error(e) => bail!("download failed: {e}"),
                    DownloadProgressItem::DownloadError => failed = true,
                    _ => {}
                }
            }
            if failed {
                bail!("no provider could serve the file");
            }
            self.blobs
                .tags()
                .set(format!("tethersys-in/{hash}"), hash)
                .await?;
            if let Some(dir) = dest.parent() {
                tokio::fs::create_dir_all(dir).await?;
            }
            let abs = std::path::absolute(dest)?;
            self.blobs.export(hash, &abs).await?;
            Ok(abs)
        }

        /// Drop our hold on a file so the store may reclaim the space.
        pub(crate) async fn purge_file(&self, hash: &str) -> Result<()> {
            let tags = self.blobs.tags();
            tags.delete(format!("tethersys-out/{hash}")).await?;
            tags.delete(format!("tethersys-in/{hash}")).await?;
            Ok(())
        }
    }

    /// Keep only the final path component so a hostile name cannot escape the download dir.
    fn sanitize(name: &str) -> String {
        // Split on both separators: an offer from a Windows peer must be safe on Unix and back.
        let base = name
            .rsplit(['/', '\\'])
            .find(|s| !s.is_empty())
            .unwrap_or("")
            .trim_start_matches(':');
        if base.is_empty() || base == "." || base == ".." || base.contains(':') {
            "file".into()
        } else {
            base.to_string()
        }
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn sanitize_strips_paths() {
            assert_eq!(super::sanitize("../../etc/passwd"), "passwd");
            assert_eq!(super::sanitize("C:\\x\\evil.exe"), "evil.exe");
            assert_eq!(super::sanitize("C:"), "file");
            assert_eq!(super::sanitize(".."), "file");
            assert_eq!(super::sanitize("report.pdf"), "report.pdf");
        }
    }
}
