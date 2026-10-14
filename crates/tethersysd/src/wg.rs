//! WireGuard hub: hands out /32 addresses on one interface and adds or removes peers.
//!
//! Commands go through a [`Runner`] so the logic is testable without root or a kernel
//! module. In production the runner shells out to `wg`.

use std::{net::Ipv4Addr, process::Command};

use anyhow::{Context, Result, bail};

pub trait Runner: Send + Sync {
    fn wg(&self, args: &[&str]) -> Result<String>;
}

pub struct SystemWg;

impl Runner for SystemWg {
    fn wg(&self, args: &[&str]) -> Result<String> {
        let out = Command::new("wg")
            .args(args)
            .output()
            .context("run `wg` (is wireguard-tools installed?)")?;
        if !out.status.success() {
            bail!(
                "wg {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }
}

pub struct Hub {
    pub iface: String,
    pub endpoint: String,
    pub net: Ipv4Addr,
    pub prefix: u8,
    pub server_pub: String,
    runner: Box<dyn Runner>,
}

impl Hub {
    pub fn new(iface: &str, endpoint: &str, subnet: &str, runner: Box<dyn Runner>) -> Result<Self> {
        let (net, prefix) = subnet
            .split_once('/')
            .context("--wg-subnet must look like 10.77.0.0/24")?;
        let net: Ipv4Addr = net.parse().context("bad subnet address")?;
        let prefix: u8 = prefix.parse().context("bad subnet prefix")?;
        if !(16..=30).contains(&prefix) {
            bail!("subnet prefix must be between /16 and /30");
        }
        let server_pub = runner
            .wg(&["show", iface, "public-key"])
            .with_context(|| format!("read public key of {iface}"))?;
        Ok(Self {
            iface: iface.into(),
            endpoint: endpoint.into(),
            net,
            prefix,
            server_pub,
            runner,
        })
    }

    pub fn subnet(&self) -> String {
        format!("{}/{}", self.net, self.prefix)
    }

    /// Host number 1 is the server; clients get 2 and up.
    pub fn capacity(&self) -> u32 {
        (1u32 << (32 - self.prefix)) - 3
    }

    pub fn ip(&self, host: u32) -> [u8; 4] {
        (u32::from(self.net) + host).to_be_bytes()
    }

    pub fn add_peer(&self, wg_pub: &str, ip: [u8; 4]) -> Result<()> {
        let allowed = format!("{}/32", Ipv4Addr::from(ip));
        self.runner
            .wg(&["set", &self.iface, "peer", wg_pub, "allowed-ips", &allowed])
            .map(|_| ())
    }

    pub fn remove_peer(&self, wg_pub: &str) -> Result<()> {
        self.runner
            .wg(&["set", &self.iface, "peer", wg_pub, "remove"])
            .map(|_| ())
    }
}

/// WireGuard public keys are 32 bytes of base64. Reject anything else before it reaches `wg`.
pub fn valid_key(k: &str) -> bool {
    data_encoding::BASE64
        .decode(k.as_bytes())
        .is_ok_and(|b| b.len() == 32)
}

#[cfg(test)]
pub mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone, Default)]
    pub struct FakeWg(pub Arc<Mutex<Vec<String>>>);

    impl Runner for FakeWg {
        fn wg(&self, args: &[&str]) -> Result<String> {
            self.0.lock().unwrap().push(args.join(" "));
            Ok("c2VydmVyLXB1YmxpYy1rZXktYmFzZTY0LWVuY29kZWQ9".into())
        }
    }

    #[test]
    fn addressing() {
        let hub = Hub::new(
            "wg0",
            "vpn.example.com:51820",
            "10.77.0.0/24",
            Box::new(FakeWg::default()),
        )
        .unwrap();
        assert_eq!(hub.capacity(), 253);
        assert_eq!(hub.ip(2), [10, 77, 0, 2]);
        assert!(Hub::new("wg0", "x:1", "10.77.0.0/8", Box::new(FakeWg::default())).is_err());
        assert!(valid_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
        assert!(!valid_key("AAAA; rm -rf /"));
    }
}
