# Pulsar relay server

A standalone **Rust** (tokio, UDP) rendezvous + relay server. See `../CLAUDE.md`
for the product and `../pulsar-proto` for the wire format.

> `cargo` is a rustup proxy honoring this repo's own `rust-toolchain.toml`
> (current stable). If you hit an edition-2024 error, run `rustup update stable`
> once. (`../CLAUDE.md` / `../pulsar-proto` refs assume the umbrella checkout at
> `~/Projects/pulsar/`; in a standalone clone see the GitHub repos instead.)

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
are GC'd (`DEVICE_TTL` 30 s / `SESSION_TTL` 120 s; sweep every 10 s, plus a slow
60 s pass for pubkey mappings/meters).

Also in the code (beyond the three roles above):

- **Stable identity**: `by_pubkey` maps pubkey → DeviceId so a returning device
  keeps its 9-digit ID (`PUBKEY_TTL` 30 days, `MAX_PUBKEY_MAPPINGS` 100k with
  oldest-offline eviction).
- **Hardening**: protocol-version gate on `Register` (wire-compat `ErrCode::Protocol`
  reply), per-IP Register throttle, anti-reflection caps (`MAX_RELAY_PAYLOAD` 64 KB,
  `MAX_HELLO_LEN` on both `hello` and `answer`, `MAX_NAME_LEN`), session-ownership
  checks on `Accept`/`RelayData` (anti-hijack), `ClientMsg::Bye`.
- Note `PeerMsg::Hello/HelloAck` (in pulsar-proto) is the relay-less direct-IP
  path — the relay never sees it.

## Run

```bash
cargo run -p pulsar-relay            # binds 0.0.0.0:21116
cargo run -p pulsar-relay -- --port 5000
PULSAR_RELAY_BIND=127.0.0.1:21116 cargo run -p pulsar-relay
```

### Bandwidth limits (operator, optional — default unlimited)

Cap the **relayed** traffic (the `RelayData` the server forwards) by **device**, by
**source IP**, and/or **per relay session**, on two axes — forward **rate** (bytes/s) and
cumulative data **volume** (bytes). Every limit is off by default (unlimited). Over-limit
datagrams are silently dropped (UDP — the stream adapts). Flags (each also an env var):

```bash
pulsar-relay --user-rate 10mbit --user-data 5gb     # per-device: 10 Mbit/s, 5 GB total
pulsar-relay --ip-rate 50mbit  --ip-data 20gb       # per-source-IP caps
pulsar-relay --session-rate 10mbit --session-data 2gb  # per-SESSION caps (see below)
PULSAR_RELAY_USER_RATE=10mbit PULSAR_RELAY_USER_DATA=5gb pulsar-relay
```

**Per-session vs per-device:** `--user-rate`/`--ip-rate` are SHARED across all of a device's
(or IP's) traffic — two split-screen panes from one device contend for one bucket. `--session-rate`
caps **each relay session independently**, so each stream gets the full budget. It also doubles
as an **encoder hint**: the relay advertises the per-session rate to the connecting client
(`PeerFound.rate_cap_kbps`, protocol v3), so a relayed client **starts its encoder at/below the
cap** instead of blasting its full target into the throttled pipe and waiting ~20 s for the
loss-driven ABR to ramp down. So prefer `--session-rate` when the goal is smooth per-stream
quality on a metered relay; use `--user-rate`/`--ip-rate` for abuse/DoS volume limits.

Units: rates accept bit (`mbit`/`gbit`/`mbps`, bare `m`/`g` = bits) or byte (`mb`/`gb`,
`mbyte`) suffixes; sizes accept `mb`/`gb`/`tb` (1000-based) or `mib`/`gib` (1024-based).
**The same flags/env work for the desktop app's relay mode** (`pulsar --relay
--session-rate 10mbit …`) — both run the same `Relay` (`pulsar_relay::Limits`).

### Authentication (operator, optional — default OPEN)

A relay can require a **password**, a **TOTP (2FA) code**, or both before a device may
register, and can advertise/enforce **end-to-end encryption**. Everything is off by
default: an unconfigured relay stays open, exactly as before.

```bash
pulsar-relay --auth-password s3cret                 # password only
pulsar-relay --auth-totp JBSWY3DPEHPK3PXP           # 2FA only (base32 secret)
pulsar-relay --auth-password s3cret --auth-totp …   # both = MFA
pulsar-relay --require-e2e                          # advertise + enforce E2E
PULSAR_RELAY_AUTH_PASSWORD=… PULSAR_RELAY_AUTH_TOTP=… PULSAR_RELAY_REQUIRE_E2E=1 pulsar-relay
```

The raw password never travels the (plaintext UDP) control wire: the relay answers an
unauthenticated `Register` with a per-attempt challenge nonce and the client returns
`SHA-256(nonce || password)`. The nonce is stateless — `SHA-256(server_secret || ip ||
30s-window)`, current and previous window accepted — so there is nothing per-client to
track or GC on the single-task loop. TOTP is RFC 6238 (HMAC-SHA1, 6 digits, 30 s, ±1 step).

**Enrolling 2FA** — `--generate-totp` prints a scannable QR, the manual-entry code for
when a QR can't be scanned, and the flag to start with. Nothing is stored, so re-running
mints a NEW secret; pass an existing `--auth-totp` alongside it to re-display that
secret's QR instead of rotating it:

```bash
pulsar-relay --generate-totp                        # new secret + QR + manual code
pulsar-relay --generate-totp --auth-totp <secret>   # re-show an existing enrollment
```

`--require-e2e` is a policy flag, not a new cipher: Pulsar sessions are **always**
end-to-end encrypted (the relay only ever forwards sealed blobs and knows only which id
is talking to which). The flag makes the relay advertise that policy to clients and
refuse to rendezvous a `Connect` that isn't carrying a real handshake.

It's a single self-contained binary — easy to self-host. Docker (static musl
build, `scratch` base; release.yml publishes amd64+arm64 to GHCR on release):

```bash
docker run -d --name pulsar-relay -p 21116:21116/udp ghcr.io/pulsardesk/relay
docker run -d -p 21116:21116/udp ghcr.io/pulsardesk/relay --session-rate 10mbit
```

The desktop app's relay endpoint is user-configurable, so point it at your own.
The desktop app can also run this same `Relay` itself: `pulsar --relay …`
(`relay_mode.rs` in pulsar-desktop).

## Test

```bash
cargo test -p pulsar-relay
```

`tests/relay_flow.rs` drives the server with raw UDP sockets: registration,
rendezvous, accept, and bidirectional relay forwarding.

## Layout

- `src/lib.rs` — the `Relay` (bind / run / handlers / registry) + ~10 in-crate
  `#[tokio::test]` unit tests.
- `src/limits.rs` — `Limits` + `parse_rate`/`parse_size` (unit-tested).
- `src/auth.rs` — `RelayAuth` (password / TOTP / require-E2E), the stateless challenge
  nonce, RFC 6238 TOTP + base32, and the QR/manual-code enrollment helpers (unit-tested).
- `src/main.rs` — clap CLI (`--bind` / `--host` / `--port`, the six limit flags, the
  three auth flags and `--generate-totp`, all env-configurable).
- `tests/relay_flow.rs` — integration tests (registration, stable-ID
  re-registration, heartbeat auth, offline target, full rendezvous + relay).
