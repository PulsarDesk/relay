# Operations — run, limits, auth, Docker

Part of the relay agent docs — index: [`CLAUDE.md`](../../CLAUDE.md).

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

**Durable access keys (protocol v5):** once a device satisfies the interactive factors
(password / TOTP), the relay issues an access key (`auth::issue_key`) the client stores and
replays, so a user is prompted only on a device's first connection. The key is
`hex(issued_at || mac)`, bound to the device's pubkey, valid 365 days, and signed by a key
DERIVED from the relay's current credentials — keys survive a restart, and changing the
password or TOTP secret invalidates every key ever issued. No key database.

It's a single self-contained binary — easy to self-host. Docker (static musl
build, `scratch` base; release.yml publishes amd64+arm64 to GHCR on release):

```bash
docker run -d --name pulsar-relay -p 21116:21116/udp ghcr.io/pulsardesk/relay
docker run -d -p 21116:21116/udp ghcr.io/pulsardesk/relay --session-rate 10mbit
```

The desktop app's relay endpoint is user-configurable, so point it at your own.
The desktop app can also run this same `Relay` itself: `pulsar --relay …`
(`relay_mode.rs` in pulsar-desktop).
