//! Two-device smoke test over the real internet.
//!
//!   device A:  cargo run --example chat -- ./a
//!              (prints an invite)
//!   device B:  cargo run --example chat -- ./b <invite>
//!
//! Then type lines to chat, `/file <path>` to send a file, `/link` to see the path type.
//! Add a server ticket as TETHERSYS_SERVER=<ticket> to try the Hybrid profile.

use std::time::Duration;

use tethersys::{Config, Event, Node, Profile, ServerTicket};
use tokio::io::{AsyncBufReadExt, BufReader};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let dir = args.next().unwrap_or_else(|| "./chat-state".into());
    let invite = args.next();
    let profile = match std::env::var("TETHERSYS_SERVER") {
        Ok(t) => Profile::Hybrid(ServerTicket::decode(&t)?),
        Err(_) => Profile::Public,
    };
    let mut cfg = Config::new(hostname(), profile).data_dir(&dir);
    cfg.auto_accept_files = Some(std::path::PathBuf::from(&dir).join("downloads"));
    let node = Node::spawn(cfg).await?;
    node.online(Duration::from_secs(10)).await;
    println!("node {}", node.id());

    match invite {
        Some(inv) => {
            let host = node.join(&inv).await?;
            println!("paired with {}", host.name);
        }
        None if node.peers().is_empty() => {
            println!(
                "invite (run the other side with this):\n{}",
                node.invite(Duration::from_secs(900), 1).encode()
            );
        }
        None => {}
    }

    let mut events = node.events();
    tokio::spawn(async move {
        while let Ok(ev) = events.recv().await {
            match ev {
                Event::Message {
                    body, from_mailbox, ..
                } => {
                    println!(
                        "> {}{}",
                        String::from_utf8_lossy(&body),
                        if from_mailbox {
                            " (delivered later)"
                        } else {
                            ""
                        }
                    )
                }
                Event::FileProgress { .. } => {}
                other => println!("[{other:?}]"),
            }
        }
    });

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = lines.next_line().await? {
        let Some(peer) = node.peers().first().map(|p| p.id) else {
            println!("not paired yet");
            continue;
        };
        let result = if let Some(path) = line.strip_prefix("/file ") {
            node.send_file(peer, path.trim())
                .await
                .map(|o| format!("offered {}", o.name))
        } else if line == "/link" {
            Ok(format!("{:?}", node.link(peer)))
        } else {
            node.send(peer, "chat", line)
                .await
                .map(|l| format!("sent ({l:?})"))
        };
        match result {
            Ok(s) => println!("  {s}"),
            Err(e) => println!("  error: {e:#}"),
        }
    }
    Ok(())
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "device".into())
}
