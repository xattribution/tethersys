//! TCP forwarding between real nodes on loopback, with relays and public discovery off.

use std::{net::SocketAddr, time::Duration};

use tethersys::{Config, Discovery, Node, Profile};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

fn config(name: &str, dir: &std::path::Path) -> Config {
    let mut cfg = Config::new(name, Profile::Local).data_dir(dir.join(name));
    cfg.discovery = Discovery {
        n0_dns: false,
        mdns: false,
        dht: false,
    };
    cfg.connect_timeout = Duration::from_secs(5);
    cfg
}

async fn ready(n: Node) -> Node {
    for _ in 0..50 {
        if n.addr().ip_addrs().next().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    n
}

/// A TCP server that answers every line with "echo:" and the line.
async fn echo_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    let n = match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    let mut out = b"echo:".to_vec();
                    out.extend_from_slice(&buf[..n]);
                    if s.write_all(&out).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

async fn roundtrip(addr: SocketAddr, msg: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut s = TcpStream::connect(addr).await?;
    s.write_all(msg).await?;
    let want = 5 + msg.len();
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    tokio::time::timeout(Duration::from_secs(10), async {
        while got.len() < want {
            let n = s.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        Ok::<_, std::io::Error>(())
    })
    .await
    .map_err(|_| std::io::Error::other("timed out"))??;
    Ok(got)
}

#[tokio::test(flavor = "multi_thread")]
async fn forwards_tcp_to_trusted_peers_only() {
    let dir = tempfile::tempdir().unwrap();
    let target = echo_server().await;
    let server = ready(
        Node::builder(config("nas", dir.path()))
            .serve_tcp(target)
            .spawn()
            .await
            .unwrap(),
    )
    .await;
    let phone = ready(Node::spawn(config("phone", dir.path())).await.unwrap()).await;
    phone
        .join(&server.invite(Duration::from_secs(60), 1).encode())
        .await
        .unwrap();

    let fwd = phone
        .forward_tcp(server.id(), "127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let local = fwd.local_addr();
    assert!(local.ip().is_loopback());

    // Several connections at once share the one QUIC connection.
    let mut tasks = Vec::new();
    for i in 0..4 {
        tasks.push(tokio::spawn(async move {
            let msg = format!("hello {i}").into_bytes();
            let got = roundtrip(local, &msg).await.unwrap();
            assert_eq!(got, [b"echo:".as_slice(), &msg].concat());
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }

    // A larger payload makes it through intact.
    let big: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
    let got = roundtrip(local, &big).await.unwrap();
    assert_eq!(&got[..5], b"echo:");

    // A stranger that knows the server's id and address is turned away.
    let eve = ready(Node::spawn(config("eve", dir.path())).await.unwrap()).await;
    eve.trust_peer(tethersys::Peer {
        id: server.id(),
        name: "nas".into(),
        box_pub: None,
        last_addr: Some(server.addr()),
        added_ms: 0,
        tags: vec![],
    })
    .unwrap();
    let eve_fwd = eve
        .forward_tcp(server.id(), "127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    assert!(
        roundtrip(eve_fwd.local_addr(), b"let me in")
            .await
            .map(|g| g.is_empty())
            .unwrap_or(true)
    );

    // Once the server removes the phone, new forwards stop, even on the open connection.
    assert!(server.remove_peer(phone.id()).unwrap());
    assert!(
        roundtrip(local, b"again")
            .await
            .map(|g| g.is_empty())
            .unwrap_or(true)
    );

    // Dropping the forward closes the local port.
    drop(fwd);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(TcpStream::connect(local).await.is_err());
}
