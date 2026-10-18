# Internals — roles, registry, layout

Part of the relay agent docs — index: [`CLAUDE.md`](../../CLAUDE.md).

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

## Code layout

- `src/lib.rs` — the `Relay` (bind / run / handlers / registry) + ~10 in-crate
  `#[tokio::test]` unit tests.
- `src/limits.rs` — `Limits` + `parse_rate`/`parse_size` (unit-tested).
- `src/auth.rs` — `RelayAuth` (password / TOTP / require-E2E), the stateless challenge
  nonce, durable access keys (`issue_key`), RFC 6238 TOTP + base32, and the QR/manual-code enrollment helpers (unit-tested).
- `src/main.rs` — clap CLI (`--bind` / `--host` / `--port`, the six limit flags, the
  three auth flags and `--generate-totp`, all env-configurable).
- `tests/relay_flow.rs` — integration tests (registration, stable-ID
  re-registration, heartbeat auth, offline target, full rendezvous + relay).
