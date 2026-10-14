# Adding tethersys to an app

Written for a coding agent (Claude Code) and for humans. Read this file, then `docs/ARCHITECTURE.md` only if you need the why.

## 1. Decide three things

| Question | Options | Default |
|---|---|---|
| Which profile? | `Public`, `Local`, `Sovereign`, or `Hybrid(ticket)` / `SelfHosted(ticket)` | `Public`. Only use a server profile if the app needs offline delivery, a file cache, a private relay or tunnels |
| Which language binding? | Rust crate, Kotlin (Android), Swift (iOS/macOS), C# (Windows), Python (scripts/tests) | Match the app |
| Which services? | messages, request/response, files, topics, spaces, tunnels, custom ALPN | Only what the app needs; unused services cost nothing |

## 2. Add the dependency

**Rust** (desktop apps, Tauri, CLI, services):

```toml
[dependencies]
tethersys = { git = "https://github.com/Xattribution/tethersys" }
tokio = { version = "1", features = ["full"] }
```

**Android / iOS / Windows**: build the FFI library and generated bindings. See [section 6](#6-native-builds).

## 3. Start one node per app process

Create it once at startup, keep it in an app-wide singleton, and subscribe to events once.

```rust
use tethersys::{Config, Event, Node, Profile, ServerTicket};

let profile = match option_env!("TETHERSYS_SERVER") {
    Some(t) => Profile::Hybrid(ServerTicket::decode(t)?),
    None => Profile::Public,
};
let mut cfg = Config::new(device_name, profile).data_dir(app_data_dir.join("tethersys"));
cfg.auto_accept_files = Some(downloads_dir);       // omit to approve offers in the UI
let node = Node::spawn(cfg).await?;

let mut events = node.events();
tokio::spawn(async move {
    while let Ok(ev) = events.recv().await {
        match ev {
            Event::Message { from, channel, body, .. } => { /* route by channel */ }
            Event::FileOffered(offer) => { /* show accept prompt or ignore if auto */ }
            Event::LinkChanged { peer, link, .. } => { /* update a connection badge */ }
            _ => {}
        }
    }
});
```

`data_dir` holds the identity, trust list, blob store and spaces. Platform locations: Android `context.filesDir`, iOS Application Support, Windows `%APPDATA%\<app>`. Back it up with the app's data; losing it means re-pairing.

## 4. Pair devices

```rust
// Device A: show this as a QR code or share link. One use, 15 minutes.
let code = node.invite(Duration::from_secs(900), 1).encode();
// Device B: scan or paste.
let host = node.join(&code).await?;
```

For a fleet, use `invite(ttl, uses: 50)` or `invite_tagged(.., vec!["kiosk".into()])` and read `peer.tags` to assign roles.

## 5. Recipes by app type

**Messaging / notifications**

```rust
node.send(peer, "chat", serde_json::to_vec(&msg)?).await?;   // returns Direct, Relayed or Queued
```
Use one channel per message kind. Deduplication is built in, so retries are safe.

**Commands between devices (RPC)**

```rust
node.on_request("status", |_from, _body| async { Ok(serde_json::to_vec(&status())?.into()) });
let reply = node.request(peer, "status", vec![]).await?;   // live only, errors if offline
```

**File transfer**

```rust
let offer = node.send_file(peer, &path).await?;          // receiver gets Event::FileOffered
node.accept_file(&offer, dest).await?;                   // on the receiver; resumes after drops
node.purge_file(&offer.hash).await?;                     // free space once done
```

**Shared state / data sync**

```rust
let settings = node.space("settings").await?;           // all paired peers, or space_with(name, members)
settings.set("theme", "dark").await?;
let theme = settings.get("theme");
// Remote writes arrive as Event::SpaceChanged { space, key, .. }; re-read the key then.
```
Values are bytes. For collaborative documents, store Automerge or Yjs updates as values keyed by document id.

**Live fan-out (presence, cursors, telemetry)**

```rust
let room = node.topic("room-42").await?;
room.publish(bytes).await?;                              // receivers get Event::TopicMessage
```

**Device-level VPN**

```rust
let t = node.tunnel().await?;          // needs a server with tunnels on
let conf = t.wg_quick_config();        // hand to WireGuard on the platform
```
Android: `com.wireguard.android:tunnel` (`GoBackend`). iOS: WireGuardKit in a Network Extension. Windows: `wireguard-nt` or the WireGuard service with the config file.

**Your own protocol**

```rust
let node = Node::builder(cfg).protocol(b"myapp/video/1", MyHandler).spawn().await?;
let conn = node.endpoint().connect(peer, b"myapp/video/1").await?;   // raw QUIC streams and datagrams
```
Custom protocols sit behind the same trust gate.

## 6. Native builds

The FFI crate exposes `TethersysNode` with string ids, byte payloads and one `EventListener` callback.

```bash
# Generate bindings from a host build
cargo build -p tethersys-ffi --release
cargo run -p tethersys-ffi --features bindgen --bin uniffi-bindgen -- \
  generate --library target/release/libtethersys_ffi.so --language kotlin --out-dir bindings/kotlin
#   --language swift  → bindings/swift      --language python → bindings/python

# Android (.so per ABI into jniLibs)
cargo install cargo-ndk
cargo ndk -t arm64-v8a -t x86_64 -o app/src/main/jniLibs build -p tethersys-ffi --release

# iOS (static lib per target, then an XCFramework)
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
cargo build -p tethersys-ffi --release --target aarch64-apple-ios
cargo build -p tethersys-ffi --release --target aarch64-apple-ios-sim
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libtethersys_ffi.a -headers bindings/swift \
  -library target/aarch64-apple-ios-sim/release/libtethersys_ffi.a -headers bindings/swift \
  -output TethersysFFI.xcframework

# Windows (tethersys_ffi.dll) and C# bindings
cargo build -p tethersys-ffi --release --target x86_64-pc-windows-msvc
cargo install uniffi-bindgen-cs --git https://github.com/NordSecurity/uniffi-bindgen-cs
uniffi-bindgen-cs --library target/x86_64-pc-windows-msvc/release/tethersys_ffi.dll --out-dir bindings/csharp
```

Kotlin usage:

```kotlin
val node = TethersysNode.start(
    FfiConfig(name = "Pixel", dataDir = filesDir.path + "/tethersys", profile = FfiProfile.PUBLIC,
              serverTicket = null, autoAcceptDir = null, hideIp = false, port = null),
    object : EventListener { override fun onEvent(event: FfiEvent) { /* post to UI thread */ } })
node.send(peerId, "chat", "hi".toByteArray())
```

Flutter and React Native: wrap the same crate with `flutter_rust_bridge` or `uniffi-bindgen-react-native`.

## 7. Rules for agents

- One `Node` per process. Never create one per screen or per request.
- Do not reimplement discovery, retries, encryption or offline queueing; they are in the library.
- Route by `channel` names, and namespace them per feature (`chat`, `sync.contacts`, `cmd.reboot`).
- Keep payloads small; anything over ~1 MiB is a file.
- Never log invite strings or the server ticket; both are credentials.
- Show link state from `Event::Connected`/`LinkChanged`; show offline status from `Event::Server`.
- Tests: copy the pattern in `crates/tethersys/tests/p2p.rs` (loopback nodes, discovery off).
