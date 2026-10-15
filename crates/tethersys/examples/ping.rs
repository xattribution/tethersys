//! Smallest useful app: pair two nodes in one process and exchange one message.
//! Builds with `--no-default-features`, so it doubles as a size check for the core.

use std::time::Duration;

use tethersys::{Config, Event, Node, Profile};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let a = Node::spawn(Config::new("a", Profile::Local)).await?;
    let b = Node::spawn(Config::new("b", Profile::Local)).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    b.join(&a.invite(Duration::from_secs(60), 1).encode()).await?;
    let mut events = b.events();
    a.send(b.id(), "ping", "hello").await?;
    while let Ok(ev) = events.recv().await {
        if let Event::Message { body, .. } = ev {
            println!("{}", String::from_utf8_lossy(&body));
            break;
        }
    }
    Ok(())
}
