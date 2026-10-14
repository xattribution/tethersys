---
name: tethersys
description: Add peer-to-peer networking (pairing, messaging, RPC, file transfer, pub/sub, data sync, offline mailbox, WireGuard tunnels) to an app using the tethersys library. Use when an app needs devices to talk to each other with or without a server.
---

1. Read `INTEGRATION.md` in the tethersys repo. It is the complete integration guide.
2. Pick the profile and services with the user's app in mind, using the tables in section 1.
3. Add one `Node` singleton at app startup with a persistent `data_dir`.
4. Wire `node.events()` into the app's state layer once.
5. Implement only the recipes the app needs from section 5.
6. For Android, iOS or Windows apps, follow section 6 to build the FFI library and bindings.
7. Follow the rules in section 7. Write tests in the style of `crates/tethersys/tests/p2p.rs`.
