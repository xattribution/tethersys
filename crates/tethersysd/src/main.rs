use std::{net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::Result;
use clap::Parser;
use tethersysd::{Options, Server, wg};

/// Optional server for tethersys networks: directory, sealed mailbox, file cache, WireGuard hub.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// State directory (identity, token, members, mail, cached files).
    #[arg(long, env = "TETHERSYSD_DATA", default_value = "./data")]
    data: PathBuf,
    /// UDP port for the tethersys endpoint.
    #[arg(long, env = "TETHERSYSD_PORT", default_value_t = 47711)]
    port: u16,
    /// Network token. Generated on first launch if omitted.
    #[arg(long, env = "TETHERSYSD_TOKEN")]
    token: Option<String>,
    /// URL of the iroh-relay running alongside, e.g. https://relay.example.com
    #[arg(long, env = "TETHERSYSD_RELAY_URL")]
    relay_url: Option<iroh::RelayUrl>,
    /// Public IP:port to advertise for direct connections, e.g. 203.0.113.7:47711
    #[arg(long, env = "TETHERSYSD_PUBLIC_ADDR")]
    public_addr: Option<SocketAddr>,
    /// Days to hold undelivered mail.
    #[arg(long, env = "TETHERSYSD_MAIL_DAYS", default_value_t = 14)]
    mail_days: u64,
    /// Hours to keep cached files for offline receivers.
    #[arg(long, env = "TETHERSYSD_FILE_HOURS", default_value_t = 72)]
    file_hours: u64,
    /// WireGuard interface to manage (enables tunnels), e.g. wg0
    #[arg(long, env = "TETHERSYSD_WG_IFACE")]
    wg_iface: Option<String>,
    /// host:port clients send WireGuard packets to.
    #[arg(long, env = "TETHERSYSD_WG_ENDPOINT")]
    wg_endpoint: Option<String>,
    #[arg(long, env = "TETHERSYSD_WG_SUBNET", default_value = "10.77.0.0/24")]
    wg_subnet: String,
    #[arg(long, env = "TETHERSYSD_WG_LEASE_HOURS", default_value_t = 24)]
    wg_lease_hours: u64,
    /// Print the ticket and exit.
    #[arg(long)]
    print_ticket: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,iroh=warn,iroh_blobs=warn".into()),
        )
        .init();
    let a = Args::parse();
    let mut opts = Options::new(&a.data);
    opts.port = a.port;
    opts.token = a.token;
    opts.relay = a.relay_url;
    opts.public_addr = a.public_addr;
    opts.mail_ttl = Duration::from_secs(a.mail_days * 24 * 3600);
    opts.blob_ttl = Duration::from_secs(a.file_hours * 3600);
    opts.wg_lease = Duration::from_secs(a.wg_lease_hours * 3600);
    if let Some(iface) = a.wg_iface {
        let endpoint = a
            .wg_endpoint
            .ok_or_else(|| anyhow::anyhow!("--wg-endpoint is required with --wg-iface"))?;
        opts.wg = Some(wg::Hub::new(
            &iface,
            &endpoint,
            &a.wg_subnet,
            Box::new(wg::SystemWg),
        )?);
    }

    let server = Server::spawn(opts).await?;
    let ticket = server.ticket().encode();
    std::fs::write(a.data.join("ticket.txt"), &ticket)?;
    if a.print_ticket {
        println!("{ticket}");
        return server.shutdown().await;
    }
    println!("tethersysd {} running", server.id());
    println!("server ticket (paste into app config):\n{ticket}");
    shutdown_signal().await;
    server.shutdown().await
}

/// Ctrl-C locally, SIGTERM under Docker or systemd.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}
