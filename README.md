# Pulsar relay

Self-hostable **relay / rendezvous server** for
[Pulsar](https://github.com/PulsarDesk) — the free, open-source remote-desktop +
game-streaming app.

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

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
