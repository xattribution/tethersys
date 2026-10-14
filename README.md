# tether

Peer-to-peer networking you drop into any app. Pairing, messages, RPC, file transfer, pub/sub, replicated state, an offline mailbox and WireGuard tunnels, over one encrypted QUIC connection per peer. Works with no server; gets better with one.

## Quick start

**In an app (Rust):**

```toml
tether = { git = "https://github.com/jaredkotvas/tether" }
```

```rust
let node = tether::Node::spawn(tether::Config::new("laptop", tether::Profile::Public).data_dir("./state")).await?;
let invite = node.invite(Duration::from_secs(900), 1).encode();   // QR this
// other device: node.join(&invite).await?;
node.send(peer_id, "chat", "hello").await?;                        // Direct, Relayed or Queued
```

Android, iOS and Windows use the generated Kotlin, Swift and C# bindings. See [INTEGRATION.md](INTEGRATION.md).

**Optional server (any Linux VPS):**

```bash
curl -fsSL https://raw.githubusercontent.com/jaredkotvas/tether/main/deploy/install.sh | sudo bash -s install
```

It asks three questions (relay domain, email, tunnels on or off) and prints a server ticket. Paste the ticket into the app config and switch the profile to `Hybrid(ticket)`.

| Task | Command |
|---|---|
| Update | `curl -fsSL https://raw.githubusercontent.com/jaredkotvas/tether/main/deploy/install.sh \| sudo bash -s update` |
| Uninstall | `curl -fsSL https://raw.githubusercontent.com/jaredkotvas/tether/main/deploy/install.sh \| sudo bash -s uninstall` |
| Backup | `curl -fsSL https://raw.githubusercontent.com/jaredkotvas/tether/main/deploy/install.sh \| sudo bash -s backup` |
| Restore | `curl -fsSL https://raw.githubusercontent.com/jaredkotvas/tether/main/deploy/install.sh \| sudo bash -s restore ~/tether-backup-<date>.tar.gz` |
| Show ticket | `curl -fsSL https://raw.githubusercontent.com/jaredkotvas/tether/main/deploy/install.sh \| sudo bash -s ticket` |

Installs to `~/tether`. Ports: UDP 47711 (server), TCP 80/443 and UDP 7842 (relay, only with a domain), UDP 47712 (tunnels, only if enabled).

## What you get

| Layer | Without a server | With `tetherd` |
|---|---|---|
| Find peers | invite address, LAN (mDNS), DNS, Mainline DHT | + directory with live addresses |
| Reach peers | LAN, hole-punched UDP, public relays | + your own token-gated relay on 443 |
| Messages | live, deduplicated, retried | + sealed mailbox for offline peers |
| Files | resumable, BLAKE3-verified, multi-source | + 72 h cache so senders can go offline |
| Pub/sub | signed gossip topics | same |
| Data sync | signed last-writer-wins spaces, catch-up on contact | same |
| Tunnels | none | WireGuard hub with stable per-device IPs |

Profiles bundle these into five presets: `Public`, `Hybrid`, `SelfHosted`, `Local` (LAN only, no internet) and `Sovereign` (no servers at all). Diagrams, costs and the security model are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Layout

| Path | What |
|---|---|
| `crates/tether` | The library |
| `crates/tetherd` | The optional server |
| `crates/tether-ffi` | UniFFI layer and `uniffi-bindgen` |
| `bindings/` | Generated Kotlin, Swift and Python bindings |
| `deploy/` | Dockerfile, compose files, installer |
| `INTEGRATION.md` | How to add tether to an app (written for Claude Code) |
| `.claude/skills/tether` | Skill that points Claude Code at the guide |

## Try it on two machines

```bash
cargo run --example chat -- ./a            # prints an invite
cargo run --example chat -- ./b <invite>   # on the other machine
```

Type to chat, `/file <path>` to send a file, `/link` to see whether the path is direct or relayed.

## Tests

```bash
cargo test --workspace --all-features
TETHER_RELAY_BIN=$(which iroh-relay) cargo test -p tether --test relay_token -- --ignored
```

Covered: pairing and single-use invites, untrusted-peer rejection, messages and RPC, file transfer, spaces (including deletes and restart persistence), signed pub/sub, relay-only operation, the official relay's token check, offline mailbox delivery, files fetched from the server cache after the sender left, directory lookup after a peer moved, wrong-token rejection, and WireGuard lease allocation, renewal and release.
