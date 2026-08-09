<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="branding/keynoxis-wordmark-dark.svg" />
    <img src="branding/keynoxis-wordmark.svg" width="640" alt="Keynoxis" />
  </picture>
</p>

<p align="center">
  <strong>Your SSH keys stay in hardware.</strong>
</p>

<p align="center">
  <a href="https://github.com/keynoxis/keynoxis/actions/workflows/ci.yml"><img src="https://github.com/keynoxis/keynoxis/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MPL--2.0-blue" alt="MPL-2.0 license" /></a>
  <img src="https://img.shields.io/badge/platform-macOS%2026%2B-111111" alt="macOS 26+" />
  <img src="https://img.shields.io/badge/status-active-4c8c65" alt="Active product" />
</p>

**Keynoxis is an open-source hardware-backed SSH agent for macOS Secure Enclave and FIDO2 security keys. No private key files.**

Keynoxis creates and uses SSH identities in hardware-backed storage instead of keeping private keys in ordinary files. It exposes the standard SSH agent protocol, so existing tools can use hardware-backed identities without custom integrations.

The current release supports macOS. TPM-backed identities and native Windows and Linux versions are planned for future releases.

## Compatible tools

- OpenSSH
- Git over SSH
- SCP and SFTP
- rsync
- IDEs and other applications that support an SSH agent

## Hardware backends

| Backend | Status |
| --- | --- |
| FIDO2 / YubiKey resident SSH keys | Available on macOS |
| macOS Secure Enclave | Available on Apple Silicon |
| Windows with TPM-backed identities | Planned for a future release |
| Linux with TPM-backed identities | Planned for a future release |

The common SSH-agent layer is backend-independent. Each hardware provider owns its key discovery, creation and signing implementation; private key material is never passed into the agent core.

## Current macOS release

- Creates non-exportable `ECDSA P-256` SSH keys directly in Secure Enclave.
- Restores Secure Enclave identities after relaunch and signs through Apple's CryptoKit framework.
- Stores the hardware-bound encrypted key representation with public metadata; plaintext private keys never leave Secure Enclave.

- Watches for a USB YubiKey through libfido2.
- Verifies CTAP2 and credential-management support.
- Requests the FIDO2 PIN and enumerates resident credentials whose RP ID starts with `ssh:`.
- Creates named resident `ED25519-SK` credentials directly on a connected YubiKey through libfido2.
- Supports OpenSSH `ED25519-SK` and `ECDSA-SK` identities.
- Reads and updates resident credential names directly through libfido2.
- Reconstructs public keys and SHA-256 fingerprints without exporting private keys.
- Signs SSH requests directly through libfido2, without `ssh-sk-helper` or an external CLI.
- Runs a native agent on `~/.ssh/keynoxis.sock`.
- Configures the standard macOS OpenSSH client through `~/.ssh/keynoxis.conf`.
- Runs as a menu-bar application and automatically presents PIN and touch prompts.

The FIDO2 PIN is never persisted to disk. It is retained in wipe-on-drop process memory while the security key is connected because user-verification signing may require it.

## Architecture direction

```text
SSH / Git / SCP / rsync / IDE
              │
              ▼
      Keynoxis SSH Agent
              │
      Hardware provider API
         ┌────┼───────────┐
         ▼    ▼           ▼
  Secure Enclave  FIDO2 / YubiKey  TPM
```

The key model identifies its hardware backend and keeps provider-specific handles outside the public IPC model. Secure Enclave and FIDO2 identities are served concurrently through the same agent socket without changing SSH clients.

## OpenSSH integration and migration

Keynoxis writes a managed `~/.ssh/keynoxis.conf` containing its stable `IdentityAgent` socket and places `Include ~/.ssh/keynoxis.conf` first in `~/.ssh/config`. Existing SSH configuration is preserved.

When upgrading from YubiAgent, the exact managed include is replaced automatically. The legacy managed file and an inactive legacy socket are removed; user-managed files are not deleted.

## Build from source

Requirements:

```text
macOS 26+
Node.js 20+
Rust stable
libfido2 available while building
```

Commands:

```sh
npm install
npm run dev
npm test
npm run web:build
cargo test --manifest-path src-tauri/Cargo.toml
npm run build -- --bundles app
```

The macOS bundle includes libfido2 and its non-system dynamic library dependencies, so the resulting application does not require Homebrew at runtime. Their arm64 build inputs are integrity-pinned in `src-tauri/native/macos-dylib-sha256.txt`; review an upstream upgrade before updating those hashes. Local verification builds can explicitly request an ad-hoc signature; public distribution requires Apple Developer ID signing and notarization.

## Security

Please do not disclose suspected vulnerabilities in a public issue. Follow the private reporting process in [SECURITY.md](SECURITY.md).

## Distribution

Release signing, GitHub Actions configuration, Apple notarization and local
macOS release builds are documented in
[docs/MACOS_DISTRIBUTION.md](docs/MACOS_DISTRIBUTION.md).

## Contributing

Bug reports, platform research, documentation improvements and focused pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a change.

## License

Keynoxis is licensed under the [Mozilla Public License 2.0](LICENSE). Changes to MPL-covered files remain available under the MPL when distributed, while separate files may be combined with the project under different terms.
