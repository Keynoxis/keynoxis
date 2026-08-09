# Security policy

## Supported versions

The latest published Keynoxis release and the current revision on the `main` branch are supported for security fixes. Users of older releases may be asked to update before a report is investigated or a fix is provided.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

Use GitHub's **Report a vulnerability** form in the repository's Security tab. Repository maintainers should enable private vulnerability reporting before making the repository public.

Include, where possible:

- the affected revision and platform;
- the hardware backend involved;
- reproduction steps or a minimal proof of concept;
- the expected and observed security impact;
- whether credentials, PINs or private infrastructure are present in the report.

Do not include real private keys, PINs, recovery material or production credentials. Maintainers will acknowledge a report as soon as practical and coordinate disclosure after validation and remediation.

## Security scope

Security-sensitive areas include hardware-backed key lifecycle operations, PIN and biometric flows, SSH agent protocol handling, socket permissions, persisted settings, activity logs, OpenSSH configuration changes and bundled native libraries.
