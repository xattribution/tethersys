//! Checks a node against the official `iroh-relay` binary with token access control, the
//! same setup the installer deploys. Needs the binary, so it only runs when pointed at one:
//!
//!   TETHER_RELAY_BIN=/path/to/iroh-relay cargo test -p tether --test relay_token -- --ignored

use std::{process::Stdio, time::Duration};

use tether::{Config, Delivery, Discovery, LinkKind, Node, Profile, Relays};

fn cfg(name: &str, dir: &std::path::Path, url: &tether::RelayUrl, token: &str) -> Config {
    let mut c = Config::new(name, Profile::Local).data_dir(dir.join(name));
    c.discovery = Discovery {
        n0_dns: false,
        mdns: false,
        dht: false,
    };
    c.relays = Relays::Custom(vec![(url.clone(), Some(token.to_string()))]);
    c.hide_ip = true;
    c
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn official_relay_enforces_token() {
    let bin = std::env::var("TETHER_RELAY_BIN").expect("set TETHER_RELAY_BIN");
    let dir = tempfile::tempdir().unwrap();
    let conf = dir.path().join("relay.toml");
    std::fs::write(
        &conf,
        "enable_relay = true\nhttp_bind_addr = \"127.0.0.1:18781\"\nenable_metrics = false\n\n[access]\nshared_token = [\"s3cret\"]\n",
    )
    .unwrap();
    let mut relay = tokio::process::Command::new(bin)
        .args(["--dev", "--config-path"])
        .arg(&conf)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let url: tether::RelayUrl = "http://127.0.0.1:18781".parse().unwrap();

    let a = Node::spawn(cfg("alice", dir.path(), &url, "s3cret"))
        .await
        .unwrap();
    let b = Node::spawn(cfg("bob", dir.path(), &url, "s3cret"))
        .await
        .unwrap();
    assert!(a.online(Duration::from_secs(10)).await);
    assert!(b.online(Duration::from_secs(10)).await);
    b.join(&a.invite(Duration::from_secs(60), 1).encode())
        .await
        .unwrap();
    let link = a
        .send_with(b.id(), "chat", "hi", Delivery::Direct)
        .await
        .unwrap();
    assert_eq!(link, LinkKind::Relayed);

    let eve = Node::spawn(cfg("eve", dir.path(), &url, "wrong"))
        .await
        .unwrap();
    assert!(
        !eve.online(Duration::from_secs(4)).await,
        "wrong token is refused by the relay"
    );
    relay.kill().await.ok();
}
