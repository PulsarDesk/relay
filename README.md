<p align="center">
  <img width="120" height="120" src="https://raw.githubusercontent.com/PulsarDesk/.github/main/profile/logo.svg" alt="Pulsar logo">
</p>

<h1 align="center">Pulsar Relay</h1>

<p align="center">
  Run your own Pulsar server: your own device IDs and your own fallback when a direct connection isn't possible. 🛰️
</p>

<p align="center">
  <img src="https://img.shields.io/maintenance/yes/2026?style=for-the-badge" alt="Maintained">
  <a href="https://github.com/PulsarDesk/relay/releases"><img src="https://img.shields.io/github/v/release/PulsarDesk/relay?include_prereleases&style=for-the-badge" alt="Release"></a>
  <a href="https://github.com/PulsarDesk/relay/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/PulsarDesk/relay/ci.yml?branch=main&style=for-the-badge&label=CI" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/PulsarDesk/relay?style=for-the-badge" alt="License"></a>
</p>

---

## 🚀 Project Status
**Current Status:** Alpha (0.x). Pulsar works out of the box with the public relay; run your own when you want
everything on your side.

The relay gives each device its ID, helps two devices find each other, and forwards traffic when they can't connect
directly. Sessions are end-to-end encrypted, so the relay only ever sees scrambled data. Like a self-hosted RustDesk server,
but for Pulsar.

---

## 📦 Other Pulsar Repositories
- [**pulsar-desktop**](https://github.com/PulsarDesk/pulsar-desktop) - Pulsar for Windows, macOS and Linux
- [**pulsar-mobile**](https://github.com/PulsarDesk/pulsar-mobile) - Pulsar for Android
- [**pulsar-core**](https://github.com/PulsarDesk/pulsar-core) - The shared engine behind both apps

---

## ⚡ Running a relay
- **Docker (easiest):**

```bash
docker run -d --name pulsar-relay --restart unless-stopped -p 21116:21116/udp ghcr.io/pulsardesk/relay
```

- **Binary:** download `pulsar-relay` for your system from the [latest release](https://github.com/PulsarDesk/relay/releases/latest)
  (Linux x64 / arm64, Windows x64, macOS) and run it.
- **On your phone:** the [Android app](https://github.com/PulsarDesk/pulsar-mobile) can run a relay for your Wi-Fi
  (Settings).

Open **UDP port 21116** on your firewall. Then in Pulsar on every device: Settings -> Network -> relay
`your-server:21116`.

Optional password, 2FA and bandwidth limits: `pulsar-relay --help` and [docs/self-hosting.md](docs/self-hosting.md).

### Where it has been tested
| Where | Status |
|---|---|
| Linux x64, Docker | ✅ runs the public relay |
| Android (inside the app) | ✅ |
| Linux arm64, Windows, macOS binaries | ❔ built on every release, not tested |

---

## 🐞 Reporting a bug
[Open an issue](https://github.com/PulsarDesk/relay/issues/new/choose) and include:

- Relay version (`pulsar-relay --version`) and how you run it (Docker, binary, phone)
- Your options, **without passwords or 2FA secrets**
- What the app shows when it fails, and the relay's output around that time

---

## 🛠️ Requirements
**To run:** any Linux, Windows or macOS machine reachable on one UDP port. It uses very little CPU and memory; the
bandwidth it needs depends on how many sessions can't connect directly.

**For contributors / development:** Rust stable.

---

## 🤝 Contributing
Everyone can open [issues](https://github.com/PulsarDesk/relay/issues) and pull requests. Irrelevant or abusive
issues may be closed or removed. Commits follow [Conventional Commits](https://www.conventionalcommits.org).

### Development Guide
```bash
git clone https://github.com/PulsarDesk/relay.git
cd relay
cargo run --release
cargo test
```

---

## 📄 License
Pulsar is licensed under **GNU GPLv3 or later** (GPL-3.0-or-later). See the [LICENSE](LICENSE) file for details.
