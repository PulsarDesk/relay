# Self-hosting details

Options for running your own relay. Back to the [README](../README.md).

The relay does three jobs:

- **Issues device IDs** — assigns each device its stable 9-digit ID
  (mapped by public key, so a device keeps its ID across restarts).
- **Coordinates P2P** — brokers the rendezvous + UDP hole-punch between two peers.
- **Relays traffic** — forwards ciphertext when direct P2P fails (NAT/firewall).

It is **zero-knowledge**: all session traffic is end-to-end encrypted (X25519 +
ChaCha20-Poly1305), so the relay only ever forwards opaque ciphertext. Run your
own and you own identity distribution + fallback transport end to end.

## Run

```bash
cargo run --release            # binds the default UDP port
cargo run --release -- --help  # options (bind addr/port, buffers, …)
```

### Authentication (optional — default OPEN)

A relay can require a **password**, a **TOTP (2FA) code**, or both, and can advertise +
enforce end-to-end encryption. All off by default.

```bash
pulsar-relay --auth-password s3cret                 # password only
pulsar-relay --auth-totp JBSWY3DPEHPK3PXP           # 2FA only (base32 secret)
pulsar-relay --auth-password s3cret --auth-totp …   # both = MFA
pulsar-relay --require-e2e                          # advertise + enforce E2E
```

The raw password never travels the plaintext UDP control wire — the relay issues a
per-attempt challenge nonce and the client returns `SHA-256(nonce || password)`. TOTP is
RFC 6238 (HMAC-SHA1, 6 digits, 30 s).

**Enrolling 2FA** prints a scannable QR plus a manual-entry code for when a QR can't be
scanned:

```bash
pulsar-relay --generate-totp                        # new secret + QR + manual code
pulsar-relay --generate-totp --auth-totp <secret>   # re-show an existing enrollment
```

Pulsar sessions are **always** end-to-end encrypted (the relay forwards only sealed blobs
and knows just which id talks to which), so `--require-e2e` states and enforces that
policy rather than adding a cipher.

### Docker

```bash
docker run -d --name pulsar-relay -p 21116:21116/udp ghcr.io/pulsardesk/relay
# with per-session bandwidth limits:
docker run -d -p 21116:21116/udp ghcr.io/pulsardesk/relay --session-rate 10mbit
# or build locally:
docker build -t pulsar-relay . && docker run -d -p 21116:21116/udp pulsar-relay
```

The image is a static musl build on a `scratch` base (a few MB); the port is
**UDP**, so the `/udp` suffix matters.

## Test

```bash
cargo test
```

Depends on the shared wire protocol
[`PulsarDesk/pulsar-proto`](https://github.com/PulsarDesk/pulsar-proto)
(git dependency).

