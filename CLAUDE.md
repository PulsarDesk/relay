# Pulsar relay server

A standalone **Rust** (tokio, UDP) rendezvous + relay server. See `../CLAUDE.md`
for the product and `../pulsar-proto` for the wire format.

> `cargo` is a rustup proxy honoring `../rust-toolchain.toml` (current stable). If
> you hit an edition-2024 error, run `rustup update stable` once.

## What it does

1. **Identity** — on `Register`, assigns a unique 9-digit `DeviceId` + auth `Token`
   (this is where a device's ID comes from).
2. **Rendezvous** — on `Connect`, hands each side the other's observed public
   address so they can hole-punch a direct P2P path; forwards the opaque X25519
   handshake blobs (`hello`/`answer`).
3. **Relay fallback** — forwards `RelayData` between the two peers when P2P fails.
   Payloads are already end-to-end encrypted, so the relay is a zero-knowledge
   forwarder.

Single-task UDP event loop, so the registry needs no locks. Stale devices/sessions
are GC'd (`DEVICE_TTL` / `SESSION_TTL`).

## Run

```bash
cargo run -p pulsar-relay            # binds 0.0.0.0:21116
cargo run -p pulsar-relay -- --port 5000
PULSAR_RELAY_BIND=127.0.0.1:21116 cargo run -p pulsar-relay
```

### Bandwidth limits (operator, optional — default unlimited)

Cap the **relayed** traffic (the `RelayData` the server forwards) by **device** and/or
by **source IP**, on two axes — forward **rate** (bytes/s) and cumulative data **volume**
(bytes). Every limit is off by default (unlimited). Over-limit datagrams are silently
dropped (UDP — the stream adapts). Flags (each also an env var):

```bash
pulsar-relay --user-rate 10mbit --user-data 5gb   # per-device: 10 Mbit/s, 5 GB total
pulsar-relay --ip-rate 50mbit  --ip-data 20gb     # per-source-IP caps
PULSAR_RELAY_USER_RATE=10mbit PULSAR_RELAY_USER_DATA=5gb pulsar-relay
```

Units: rates accept bit (`mbit`/`gbit`/`mbps`, bare `m`/`g` = bits) or byte (`mb`/`gb`,
`mbyte`) suffixes; sizes accept `mb`/`gb`/`tb` (1000-based) or `mib`/`gib` (1024-based).
**The same flags/env work for the desktop app's relay mode** (`pulsar --relay
--user-rate 10mbit …`) — both run the same `Relay` (`pulsar_relay::Limits`).

It's a single self-contained binary — easy to self-host (the website shows a
`docker run … pulsar/relay` flow). The desktop app's relay endpoint is
user-configurable, so point it at your own.

## Test

```bash
cargo test -p pulsar-relay
```

`tests/relay_flow.rs` drives the server with raw UDP sockets: registration,
rendezvous, accept, and bidirectional relay forwarding.

## Layout

- `src/lib.rs` — the `Relay` (bind / run / handlers / registry).
- `src/main.rs` — clap CLI (`--bind` / `--host` / `--port`, env-configurable).
- `tests/relay_flow.rs` — integration tests.
