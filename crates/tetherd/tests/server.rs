//! Server-assisted paths: offline mailbox, cached files, directory, tunnel leases.

use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use tether::{Config, Discovery, Event, LinkKind, Node, Profile, ServerTicket};
use tetherd::{Options, Server, wg};
use tokio::sync::broadcast::Receiver;

#[derive(Clone, Default)]
struct FakeWg(Arc<Mutex<Vec<String>>>);

impl wg::Runner for FakeWg {
    fn wg(&self, args: &[&str]) -> anyhow::Result<String> {
        self.0.lock().unwrap().push(args.join(" "));
        Ok("c2VydmVyLXB1YmxpYy1rZXktYmFzZTY0LWVuY29kZWQ9".into())
    }
}

async fn server(dir: &Path, wg: Option<FakeWg>) -> Server {
    let mut o = Options::new(dir.join("server"));
    o.port = 0;
    o.wg = wg.map(|f| {
        wg::Hub::new("wg0", "vpn.example.com:51820", "10.77.0.0/24", Box::new(f)).unwrap()
    });
    let s = Server::spawn(o).await.unwrap();
    for _ in 0..50 {
        if s.endpoint().addr().ip_addrs().next().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    s
}

async fn node(name: &str, dir: &Path, ticket: &ServerTicket) -> Node {
    let mut cfg = Config::new(name, Profile::SelfHosted(ticket.clone())).data_dir(dir.join(name));
    cfg.discovery = Discovery {
        n0_dns: false,
        mdns: false,
        dht: false,
    };
    cfg.connect_timeout = Duration::from_secs(2);
    cfg.server_poll = Duration::from_millis(500);
    Node::spawn(cfg).await.unwrap()
}

async fn wait_for<T>(rx: &mut Receiver<Event>, mut f: impl FnMut(&Event) -> Option<T>) -> T {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(ev) = rx.recv().await {
                if let Some(t) = f(&ev) {
                    return t;
                }
            }
        }
    })
    .await
    .expect("event did not arrive in time")
}

async fn registered(n: &Node, rx: &mut Receiver<Event>) {
    let _ = n;
    wait_for(rx, |e| {
        matches!(
            e,
            Event::Server {
                connected: true,
                ..
            }
        )
        .then_some(())
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn offline_mailbox_and_cached_file() {
    let dir = tempfile::tempdir().unwrap();
    let srv = server(dir.path(), None).await;
    let ticket = srv.ticket();
    // The ticket survives a round trip through its string form.
    assert_eq!(ServerTicket::decode(&ticket.encode()).unwrap(), ticket);

    let a = node("alice", dir.path(), &ticket).await;
    let b = node("bob", dir.path(), &ticket).await;
    let (mut ae, mut be) = (a.events(), b.events());
    registered(&a, &mut ae).await;
    registered(&b, &mut be).await;
    assert_eq!(srv.member_count(), 2);

    let invite = a.invite(Duration::from_secs(60), 1).encode();
    b.join(&invite).await.unwrap();
    let b_id = b.id();

    // Bob goes offline. Alice's message and file still go out, through the server.
    b.shutdown().await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let link = a.send(b_id, "chat", "while you were out").await.unwrap();
    assert_eq!(link, LinkKind::Queued);

    let src = dir.path().join("report.pdf");
    let data: Vec<u8> = (0..1_500_000u32).map(|i| (i * 7 % 256) as u8).collect();
    std::fs::write(&src, &data).unwrap();
    let (offer, link) = a
        .send_file_with(b_id, &src, tether::Delivery::Auto)
        .await
        .unwrap();
    assert_eq!(link, LinkKind::Queued);
    assert!(offer.providers.contains(&srv.id()), "server holds a copy");

    // Now alice goes offline too. Bob comes back and gets everything from the server alone.
    a.shutdown().await.unwrap();
    let b = node("bob", dir.path(), &ticket).await;
    let mut be = b.events();
    let msg = wait_for(&mut be, |e| match e {
        Event::Message {
            channel,
            body,
            from_mailbox: true,
            ..
        } if channel == "chat" => Some(body.clone()),
        _ => None,
    })
    .await;
    assert_eq!(&msg[..], b"while you were out");
    let got = wait_for(&mut be, |e| match e {
        Event::FileOffered(o) => Some(o.clone()),
        _ => None,
    })
    .await;
    let out = b
        .accept_file(&got, dir.path().join("in/report.pdf"))
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(out).unwrap(),
        data,
        "file came from the server cache"
    );
    srv.maintain().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn directory_finds_moved_peer_and_token_is_enforced() {
    let dir = tempfile::tempdir().unwrap();
    let srv = server(dir.path(), None).await;
    let ticket = srv.ticket();
    let a = node("alice", dir.path(), &ticket).await;
    let b = node("bob", dir.path(), &ticket).await;
    let (mut ae, mut be) = (a.events(), b.events());
    registered(&a, &mut ae).await;
    registered(&b, &mut be).await;
    b.join(&a.invite(Duration::from_secs(60), 1).encode())
        .await
        .unwrap();

    // Bob restarts on a new port: the address alice has on file is now stale.
    b.shutdown().await.unwrap();
    let b = node("bob", dir.path(), &ticket).await;
    let mut be = b.events();
    registered(&b, &mut be).await;
    let link = a
        .send_with(b.id(), "chat", "found you", tether::Delivery::Direct)
        .await
        .expect("directory lookup supplies the new address");
    assert_eq!(link, LinkKind::Direct);

    // A node with the wrong token cannot join the network.
    let mut bad = ticket.clone();
    bad.token = "wrong".into();
    let eve = node("eve", dir.path(), &bad).await;
    let mut ee = eve.events();
    assert!(
        tokio::time::timeout(Duration::from_secs(3), registered(&eve, &mut ee))
            .await
            .is_err()
    );
    assert!(eve.tunnel().await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn wireguard_leases() {
    let dir = tempfile::tempdir().unwrap();
    let fake = FakeWg::default();
    let srv = server(dir.path(), Some(fake.clone())).await;
    let ticket = srv.ticket();
    let a = node("alice", dir.path(), &ticket).await;
    let b = node("bob", dir.path(), &ticket).await;
    let (mut ae, mut be) = (a.events(), b.events());
    registered(&a, &mut ae).await;
    registered(&b, &mut be).await;

    let ta = a.tunnel().await.unwrap();
    let tb = b.tunnel().await.unwrap();
    assert_eq!(ta.lease.address, "10.77.0.2/32");
    assert_eq!(tb.lease.address, "10.77.0.3/32");
    let conf = ta.wg_quick_config();
    assert!(conf.contains("Endpoint = vpn.example.com:51820"));
    assert!(conf.contains("AllowedIPs = 10.77.0.0/24"));
    assert!(
        conf.contains(&ta.keys.private),
        "private key stays on the device that made it"
    );

    // Renewal with the same key keeps the address.
    let again = a.tunnel_with_keys(ta.keys.clone()).await.unwrap();
    assert_eq!(again.lease.address, ta.lease.address);

    let peers = a.tunnel_peers().await.unwrap();
    assert_eq!(peers, vec![(b.id(), "10.77.0.3".to_string())]);

    b.release_tunnel().await.unwrap();
    let log = fake.0.lock().unwrap().clone();
    assert!(
        log.iter()
            .any(|c| c.starts_with("set wg0 peer") && c.ends_with("allowed-ips 10.77.0.2/32"))
    );
    assert!(
        log.iter()
            .any(|c| c == &format!("set wg0 peer {} remove", tb.keys.public))
    );
}
