//! End-to-end tests between real nodes on loopback, with relays and public discovery off
//! so the direct path is what gets exercised.

use std::time::Duration;

use tethersys::{Config, Delivery, Discovery, Event, LinkKind, Node, Profile};
use tokio::sync::broadcast::Receiver;

async fn node(name: &str, dir: &std::path::Path) -> Node {
    let mut cfg = Config::new(name, Profile::Local).data_dir(dir.join(name));
    cfg.discovery = Discovery {
        n0_dns: false,
        mdns: false,
        dht: false,
    };
    cfg.connect_timeout = Duration::from_secs(5);
    let n = Node::spawn(cfg).await.unwrap();
    // Wait until the endpoint knows its own direct addresses, so invites carry them.
    for _ in 0..50 {
        if n.addr().ip_addrs().next().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    n
}

async fn wait_for<T>(rx: &mut Receiver<Event>, mut f: impl FnMut(&Event) -> Option<T>) -> T {
    tokio::time::timeout(Duration::from_secs(20), async {
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

async fn paired(dir: &std::path::Path) -> (Node, Node) {
    let a = node("alice", dir).await;
    let b = node("bob", dir).await;
    let invite = a.invite(Duration::from_secs(60), 1).encode();
    let host = b.join(&invite).await.expect("pairing works");
    assert_eq!(host.id, a.id());
    assert_eq!(host.name, "alice");
    assert!(a.peers().iter().any(|p| p.id == b.id() && p.name == "bob"));
    (a, b)
}

#[tokio::test(flavor = "multi_thread")]
async fn pairing_messaging_and_trust() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = paired(dir.path()).await;
    let mut b_events = b.events();

    // One-way message arrives as an event over a direct path.
    let link = a
        .send_with(b.id(), "chat", "hello bob", Delivery::Direct)
        .await
        .unwrap();
    assert_eq!(link, LinkKind::Direct);
    let body = wait_for(&mut b_events, |e| match e {
        Event::Message {
            channel,
            body,
            from_mailbox: false,
            ..
        } if channel == "chat" => Some(body.clone()),
        _ => None,
    })
    .await;
    assert_eq!(&body[..], b"hello bob");

    // Request/response.
    b.on_request("echo", |_from, body| async move {
        Ok(tethersys::Bytes::from(
            [b"echo:".as_slice(), &body].concat(),
        ))
    });
    let reply = a.request(b.id(), "echo", "ping").await.unwrap();
    assert_eq!(&reply[..], b"echo:ping");

    // A stranger is turned away even though it knows alice's address and id.
    let eve = node("eve", dir.path()).await;
    eve.trust_peer(tethersys::Peer {
        id: a.id(),
        name: "alice".into(),
        box_pub: None,
        last_addr: Some(a.addr()),
        added_ms: 0,
        tags: vec![],
    })
    .unwrap();
    assert!(
        eve.send_with(a.id(), "chat", "let me in", Delivery::Direct)
            .await
            .is_err()
    );

    // The invite was single use: replaying it fails.
    let used = a.invite(Duration::from_secs(60), 1);
    let encoded = used.encode();
    let c = node("carol", dir.path()).await;
    c.join(&encoded).await.unwrap();
    assert!(
        eve.join(&encoded).await.is_err(),
        "second redemption must fail"
    );

    // Without a server, Auto delivery to an unreachable peer is an error, not a silent drop.
    drop(c);
    let ghost = tethersys::SecretKey::generate().public();
    assert!(a.send(ghost, "chat", "x").await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn files_topics_and_spaces() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = paired(dir.path()).await;
    let mut b_events = b.events();

    // File transfer: offer, accept, verify bytes.
    let src = dir.path().join("photo.bin");
    let data: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&src, &data).unwrap();
    let offer = a.send_file(b.id(), &src).await.unwrap();
    let got = wait_for(&mut b_events, |e| match e {
        Event::FileOffered(o) => Some(o.clone()),
        _ => None,
    })
    .await;
    assert_eq!(got.hash, offer.hash);
    assert_eq!(got.name, "photo.bin");
    let out = b
        .accept_file(&got, dir.path().join("dl/photo.bin"))
        .await
        .unwrap();
    assert_eq!(std::fs::read(out).unwrap(), data);

    // Space: alice writes before bob opens it; bob catches up by reconciling.
    let sa = a.space("settings").await.unwrap();
    sa.set("theme", "dark").await.unwrap();
    sa.set("tmp", "x").await.unwrap();
    sa.delete("tmp").await.unwrap();
    let sb = b.space("settings").await.unwrap();
    // Opening already reconciles in the background; an explicit sync must also succeed.
    sb.sync_with(a.id()).await.unwrap();
    assert_eq!(sb.get("theme").as_deref(), Some(b"dark".as_slice()));
    assert_eq!(sb.get("tmp"), None, "deletes replicate");

    // Bob writes; reconciling from alice's side pulls it back.
    sb.set("lang", "en").await.unwrap();
    sa.sync_with(b.id()).await.unwrap();
    assert_eq!(sa.get("lang").as_deref(), Some(b"en".as_slice()));

    // Pub/sub: both join, alice publishes until bob's verified copy shows up.
    let mut b_events = b.events();
    let ta = a.topic("room").await.unwrap();
    let _tb = b.topic("room").await.unwrap();
    let publisher = tokio::spawn(async move {
        loop {
            let _ = ta.publish("hi room").await;
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    });
    let got = Some(
        wait_for(&mut b_events, |e| match e {
            Event::TopicMessage {
                topic,
                author,
                body,
            } if topic == "room" => Some((*author, body.clone())),
            _ => None,
        })
        .await,
    );
    publisher.abort();
    let (author, body) = got.expect("topic message arrives");
    assert_eq!(author, a.id());
    assert_eq!(&body[..], b"hi room");
}

#[tokio::test(flavor = "multi_thread")]
async fn state_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = paired(dir.path()).await;
    let (a_id, b_id) = (a.id(), b.id());
    let s = a.space("notes").await.unwrap();
    s.set("k", "v").await.unwrap();
    a.shutdown().await.unwrap();

    let a2 = node("alice", dir.path()).await;
    assert_eq!(a2.id(), a_id, "identity persists");
    assert!(a2.peers().iter().any(|p| p.id == b_id), "trust persists");
    let s2 = a2.space("notes").await.unwrap();
    assert_eq!(
        s2.get("k").as_deref(),
        Some(b"v".as_slice()),
        "space persists"
    );
    drop(b);
}

#[cfg(feature = "test-utils")]
#[tokio::test(flavor = "multi_thread")]
async fn relay_fallback_when_direct_is_impossible() {
    let dir = tempfile::tempdir().unwrap();
    let (_map, relay_url, _relay) = iroh::test_utils::run_relay_server().await.unwrap();
    let mk = |name: &str| {
        let mut cfg = Config::new(name, Profile::Local).data_dir(dir.path().join(name));
        cfg.discovery = Discovery {
            n0_dns: false,
            mdns: false,
            dht: false,
        };
        cfg.relays = tethersys::Relays::Custom(vec![(relay_url.clone(), None)]);
        cfg.hide_ip = true; // no direct paths exist, so only the relay can carry traffic
        cfg.insecure_relay_tls = true;
        cfg
    };
    let a = Node::spawn(mk("alice")).await.unwrap();
    let b = Node::spawn(mk("bob")).await.unwrap();
    assert!(
        a.online(Duration::from_secs(10)).await,
        "alice reaches the relay"
    );
    assert!(
        b.online(Duration::from_secs(10)).await,
        "bob reaches the relay"
    );
    assert!(
        a.addr().ip_addrs().next().is_none(),
        "no IP is ever advertised"
    );

    b.join(&a.invite(Duration::from_secs(60), 1).encode())
        .await
        .unwrap();
    let mut be = b.events();
    let link = a
        .send_with(b.id(), "chat", "via relay", Delivery::Direct)
        .await
        .unwrap();
    assert_eq!(link, LinkKind::Relayed);
    let body = wait_for(&mut be, |e| match e {
        Event::Message { body, .. } => Some(body.clone()),
        _ => None,
    })
    .await;
    assert_eq!(&body[..], b"via relay");
}
