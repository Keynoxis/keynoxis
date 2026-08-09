# Contributing to Keynoxis

Thanks for helping improve Keynoxis. The product is actively developed, and small, reviewable changes are the easiest to validate safely.

## Before you start

- Use GitHub Discussions or an issue for substantial design changes.
- Search existing issues before reporting a bug.
- Never include real PINs, private keys, credentials, device identifiers or private infrastructure details in issues, logs or fixtures.
- Report security vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Local development

You need macOS 26 or newer, Node.js 20 or newer, Rust stable and libfido2.

```sh
npm install
npm run dev
```

Before submitting a pull request, run:

```sh
npm test
npm run web:build
cargo fmt --manifest-path src-tauri/Cargo.toml -- --check
cargo test --manifest-path src-tauri/Cargo.toml
```

## Pull requests

- Keep the change focused and explain its user-visible effect.
- Add or update tests when behavior changes.
- Update documentation when commands, security properties or supported hardware change.
- Include screenshots for user-interface changes.
- Call out changes that affect key creation, signing, PIN handling, SSH agent behavior or on-disk state.

Contributions are accepted under the [Mozilla Public License 2.0](LICENSE), the same license that covers the project.
