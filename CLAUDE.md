# Pulsar relay server

A standalone **Rust** (tokio, UDP) rendezvous + relay server: assigns each device its
9-digit ID, hands peers each other's address for P2P hole-punching, and forwards
already-E2E-encrypted traffic when P2P fails (zero-knowledge). See `../CLAUDE.md` for the
product and `../pulsar-proto` for the wire format.

> `cargo` is a rustup proxy honoring this repo's own `rust-toolchain.toml`
> (current stable). If you hit an edition-2024 error, run `rustup update stable`
> once. (`../CLAUDE.md` / `../pulsar-proto` refs assume the umbrella checkout at
> `~/Projects/pulsar/`; in a standalone clone see the GitHub repos instead.)

This file is the **index**. Read the topic file before working in its area:

| Topic | File | Read before touching… |
| --- | --- | --- |
| Internals | [docs/agents/internals.md](docs/agents/internals.md) | the registry, stable IDs, GC/TTLs, hardening, the source layout |
| Operations | [docs/agents/operations.md](docs/agents/operations.md) | CLI flags/env, bandwidth limits, password/TOTP auth, access keys, Docker |

## Must-know rules

- Wire format = `pulsar-proto` (bincode, positional): any message change is a
  `PROTOCOL_VERSION` bump across proto/relay/core/apps.
- Single-task UDP event loop — the registry takes no locks; keep handlers non-blocking.
- **CI is fmt-gated** (`cargo fmt --all --check`): run `cargo fmt` before pushing.
- The official relay (`relay.pulsardesk.com`) redeploys from `main` when a release is cut —
  the Release workflow calls `deploy.yml` (`workflow_call`; `on: release` never fires for
  a GITHUB_TOKEN-created release). Manual redeploy: `gh workflow run "Deploy relay"`.
- The desktop app embeds this same `Relay` (`pulsar --relay …`, `relay_mode.rs`), so flag
  changes reach it too.

## Test

```bash
cargo test -p pulsar-relay
```

`tests/relay_flow.rs` drives the server with raw UDP sockets: registration,
rendezvous, accept, and bidirectional relay forwarding.
