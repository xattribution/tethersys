//! Length-prefixed postcard framing used by every tether protocol.
//!
//! Each frame is a 4-byte big-endian length followed by a postcard-encoded value.
//! A hard size cap protects both sides from memory exhaustion by a misbehaving peer.

use anyhow::{Context, Result, bail};
use iroh::endpoint::{RecvStream, SendStream};
use serde::{Serialize, de::DeserializeOwned};

/// Largest single frame tether will read or write (16 MiB). Bigger payloads belong in files.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

pub async fn write_frame<T: Serialize>(send: &mut SendStream, value: &T) -> Result<()> {
    let bytes = postcard::to_stdvec(value).context("encode frame")?;
    if bytes.len() > MAX_FRAME {
        bail!(
            "frame of {} bytes exceeds the {} byte limit",
            bytes.len(),
            MAX_FRAME
        );
    }
    send.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    send.write_all(&bytes).await?;
    Ok(())
}

pub async fn read_frame<T: DeserializeOwned>(recv: &mut RecvStream) -> Result<T> {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len)
        .await
        .context("read frame length")?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        bail!("peer sent a {len} byte frame, over the {MAX_FRAME} byte limit");
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await.context("read frame body")?;
    postcard::from_bytes(&buf).context("decode frame")
}

/// Send one request on a fresh bi stream and wait for one reply.
pub async fn call<Req: Serialize, Resp: DeserializeOwned>(
    conn: &iroh::endpoint::Connection,
    req: &Req,
) -> Result<Resp> {
    let (mut send, mut recv) = conn.open_bi().await.context("open stream")?;
    write_frame(&mut send, req).await?;
    send.finish()?;
    read_frame(&mut recv).await
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::fill(&mut out);
    out
}
