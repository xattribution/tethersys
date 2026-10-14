# tethersys

Peer-to-peer networking you drop into any app. Pairing, messages, RPC, file transfer, pub/sub, replicated state, an offline mailbox and WireGuard tunnels, over one encrypted QUIC connection per peer. Works with no server. A server is an optional add-on for apps that need offline delivery or tunnels.

## Quick start

```toml
tethersys = { git = "https://github.com/xattribution/tethersys" }
```

```rust
let node = tethersys::Node::spawn(tethersys::Config::new("laptop", tethersys::Profile::Public).data_dir("./state")).await?;
let invite = node.invite(Duration::from_secs(900), 1).encode();   // QR this
// other device: node.join(&invite).await?;
node.send(peer_id, "chat", "hello").await?;
```

That is the whole setup. No server is involved: devices find each other on the LAN, through public DNS/DHT, and through free public relays. Android, iOS and Windows use the generated Kotlin, Swift and C# bindings. [INTEGRATION.md](INTEGRATION.md) is the guide an app (or Claude Code) follows.

## The menu

Everything is on by default. To take only some pieces, turn the defaults off and list what the app needs:

```toml
tethersys = { git = "https://github.com/xattribution/tethersys", default-features = false, features = ["files", "mdns"] }
```

| Piece | Feature | Call | Use it for |
|---|---|---|---|
| Pairing | always on | `invite()` / `join()` | QR or link pairing between devices |
| Messages | always on | `send()` | Chat, notifications, commands |
| Request/response | always on | `on_request()` / `request()` | Device-to-device RPC |
| Custom protocol | always on | `Node::builder().protocol()` | Raw QUIC streams for anything else |
| Files | `files` | `send_file()` / `accept_file()` | Resumable, verified transfers |
| Topics | `pubsub` | `topic().publish()` | Live fan-out: presence, cursors, telemetry |
| Spaces | `sync` (includes `pubsub`) | `space().set()` / `get()` | Shared state that syncs when devices meet |
| LAN discovery | `mdns` | automatic | Finding devices on the same network, even offline |
| DHT discovery | `dht` | automatic | Finding devices with no company's servers involved |
| Offline mailbox | `mailbox` | automatic in `send()` | Messages to devices that are off (needs a server) |
| Tunnels | `tunnel` | `tunnel()` | Device-level VPN (needs a server) |

A minimal app (pair two devices, send a message) is 16.1 MB with only the core and 23.8 MB with every feature on.

How devices find and reach each other is a second menu, picked with one profile:

| Profile | Needs | Best for |
|---|---|---|
| `Public` (default) | Nothing | Most apps |
| `Local` | Nothing, not even internet | LAN-only or field use |
| `Sovereign` | Nothing | Zero third-party services; some strict NATs won't connect |
| `Hybrid` / `SelfHosted` | A `tethersysd` server | Apps that need the extras below |

Diagrams, costs and the security model are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Optional: `tethersysd`, for apps that need it

Only deploy a server when an app needs one of these. Everything above works without it.

| Extra | Without a server |
|---|---|
| Offline mailbox (message a device that's off) | Sends to offline devices fail |
| File cache (sender can leave before receiver downloads) | Sender must stay online |
| Private relay on port 443 | Public relays are used instead |
| WireGuard tunnels (device-level VPN) | Not available |

<details>
<summary>Server install commands</summary>

```bash
curl -fsSL https://raw.githubusercontent.com/xattribution/tethersys/main/deploy/install.sh | sudo bash -s install
```

It asks three questions (relay domain, email, tunnels on or off) and prints a server ticket. The app passes that ticket in `Profile::Hybrid(ticket)`.

| Task | Command |
|---|---|
| Update | `curl -fsSL https://raw.githubusercontent.com/xattribution/tethersys/main/deploy/install.sh \| sudo bash -s update` |
| Uninstall | `curl -fsSL https://raw.githubusercontent.com/xattribution/tethersys/main/deploy/install.sh \| sudo bash -s uninstall` |
| Backup | `curl -fsSL https://raw.githubusercontent.com/xattribution/tethersys/main/deploy/install.sh \| sudo bash -s backup` |
| Restore | `curl -fsSL https://raw.githubusercontent.com/xattribution/tethersys/main/deploy/install.sh \| sudo bash -s restore ~/tethersys-backup-<date>.tar.gz` |
| Show ticket | `curl -fsSL https://raw.githubusercontent.com/xattribution/tethersys/main/deploy/install.sh \| sudo bash -s ticket` |

Installs to `~/tethersys`. Ports: UDP 47711 (server), TCP 80/443 and UDP 7842 (relay, only with a domain), UDP 47712 (tunnels, only if enabled).

</details>

## Layout

| Path | What |
|---|---|
| `crates/tethersys` | The library |
| `crates/tethersysd` | The optional server |
| `crates/tethersys-ffi` | UniFFI layer and `uniffi-bindgen` |
| `bindings/` | Generated Kotlin, Swift and Python bindings |
| `deploy/` | Dockerfile, compose files, installer |
| `INTEGRATION.md` | How to add tethersys to an app (written for Claude Code) |
| `.claude/skills/tethersys` | Skill that points Claude Code at the guide |

## Try it on two machines

```bash
cargo run --example chat -- ./a            # prints an invite
cargo run --example chat -- ./b <invite>   # on the other machine
```

Type to chat, `/file <path>` to send a file, `/link` to see whether the path is direct or relayed.

## Tests

```bash
cargo test --workspace --all-features
TETHERSYS_RELAY_BIN=$(which iroh-relay) cargo test -p tethersys --test relay_token -- --ignored
```

Covered: pairing and single-use invites, untrusted-peer rejection, messages and RPC, file transfer, spaces (including deletes and restart persistence), signed pub/sub, relay-only operation, the official relay's token check, offline mailbox delivery, files fetched from the server cache after the sender left, directory lookup after a peer moved, wrong-token rejection, and WireGuard lease allocation, renewal and release.
