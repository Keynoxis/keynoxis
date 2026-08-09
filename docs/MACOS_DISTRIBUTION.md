# macOS signing and notarization

This guide covers direct distribution of the arm64 Keynoxis application for
macOS 26 or newer. The primary release path uses a GitHub-hosted `macos-26`
runner. A self-hosted runner is not required.

## Release model

- Pull requests and `main` use the regular CI workflow without release secrets.
- A manual run of **Release macOS** creates a signed and notarized artifact for
  testing, but does not publish a GitHub Release.
- Pushing a version tag such as `v0.1.0` runs the same checks and publishes the
  verified DMG and its SHA-256 checksum to GitHub Releases.
- The release job uses the protected GitHub Environment named `release`.

## 1. Apple account prerequisites

Direct distribution requires an active paid Apple Developer Program membership.
Create a **Developer ID Application** certificate. A Developer ID Installer
certificate is not needed because Keynoxis distributes a DMG rather than a flat
installer package.

1. Open Keychain Access on a trusted Mac.
2. Select **Certificate Assistant → Request a Certificate From a Certificate
   Authority**, enter the Apple Developer account email and save the request to
   disk.
3. In Apple Developer **Certificates, Identifiers & Profiles**, create a
   Developer ID certificate of type **Developer ID Application** using that
   request.
4. Download and open the `.cer` file. Confirm that the certificate and its
   private key appear together under **My Certificates** in Keychain Access.
5. Verify it in Terminal:

   ```sh
   security find-identity -v -p codesigning
   ```

The output must contain `Developer ID Application: … (TEAMID)`.

## 2. Export the signing certificate for GitHub

In Keychain Access, expand the Developer ID Application certificate, select the
certificate and private key together, and export them as a password-protected
`.p12` file. Use a new strong password dedicated to CI.

Copy the Base64 representation to the clipboard:

```sh
base64 -i DeveloperIDApplication.p12 | pbcopy
```

Do not place the certificate, private key, password, API key, or Base64 output
inside the repository. The relevant file extensions are blocked by `.gitignore`.

## 3. Create an App Store Connect API key

1. Open **App Store Connect → Users and Access → Integrations**.
2. Create a team API key with the minimum role that permits Developer ID
   notarization (normally **Developer**).
3. Record the **Issuer ID** and **Key ID**.
4. Download the `AuthKey_<KEY_ID>.p8` file. Apple only offers this download once.
5. Store the original key in a password manager or other protected location.

The workflow writes this key to the temporary runner directory, uses it for the
notarization request, and removes it in an `always()` cleanup step. GitHub-hosted
runners are discarded after the job.

## 4. Configure the GitHub release environment

In the repository, open **Settings → Environments**, create an environment named
`release`, and add a required reviewer. Restrict deployment branches and tags to
the release policy used by the project.

Add these environment secrets:

| Secret | Value |
| --- | --- |
| `APPLE_CERTIFICATE` | Complete Base64 text of the exported `.p12` |
| `APPLE_CERTIFICATE_PASSWORD` | Password assigned during `.p12` export |
| `APPLE_API_ISSUER` | App Store Connect Issuer ID |
| `APPLE_API_KEY` | App Store Connect Key ID |
| `APPLE_API_KEY_CONTENT` | Complete contents of `AuthKey_<KEY_ID>.p8` |

The signing identity is inferred from `APPLE_CERTIFICATE`; there is normally no
need to store `APPLE_SIGNING_IDENTITY`. If inference fails, inspect the job log
and use the exact identity printed by `security find-identity`.

Never expose release secrets to pull request jobs, especially pull requests from
forks. Keep them only in the protected `release` environment.

## 5. Test the workflow without publishing

1. Push the prepared repository to GitHub.
2. Open **Actions → Release macOS → Run workflow**.
3. Approve the `release` environment deployment.
4. Wait for the job to finish.
5. Download the `Keynoxis-<version>-macOS-arm64` workflow artifact.

The job verifies the version, tests the frontend, installs the pinned native
dependency set, builds the application, signs every Mach-O file, enables hardened
runtime, requests notarization, validates the stapled tickets, runs Gatekeeper
distribution checks, verifies the DMG, and creates a SHA-256 checksum.

The signing job has a read-only GitHub token. A separate job downloads the
already verified artifact and receives `contents: write` only when publishing a
tagged GitHub Release; Apple credentials are not exposed to that publishing job.

If Homebrew changes one of the native bottles, the integrity checks in
`src-tauri/native/macos-dylib-sha256.txt` intentionally stop the build. Do not
replace those hashes blindly. Review the dependency versions and upstream
changes, test the application, then update the hashes in a dedicated change.

## 6. Publish a release

Keep these three versions identical:

- `package.json`
- `src-tauri/Cargo.toml`
- `src-tauri/tauri.conf.json`

Commit the version change, then create and push the matching tag:

```sh
git tag -a v0.1.0 -m "Keynoxis 0.1.0"
git push origin v0.1.0
```

After environment approval, the workflow publishes the notarized DMG and its
checksum to a GitHub Release. A tag whose value does not exactly match the Tauri
version fails before signing.

## 7. Build and notarize on a local Mac

A local release build is useful before publishing, but the Mac does not need to
be registered as a self-hosted GitHub runner. Install:

- macOS 26 or newer on Apple Silicon;
- Xcode 26 and its command-line tools;
- Node.js 20;
- Rust 1.91.0;
- Homebrew `libfido2`.

```sh
xcode-select --install
brew install libfido2
npm ci
```

Install the Developer ID Application certificate in the login keychain. Keep the
App Store Connect `.p8` file outside the repository and export only its metadata
and path for the current shell:

```sh
export APPLE_SIGNING_IDENTITY='Developer ID Application: YOUR NAME (TEAMID)'
export APPLE_API_ISSUER='YOUR_ISSUER_ID'
export APPLE_API_KEY='YOUR_KEY_ID'
export APPLE_API_KEY_PATH='/absolute/protected/path/AuthKey_YOUR_KEY_ID.p8'
npm run release:macos
```

Tauri signs, submits and staples automatically when these variables are present.
Then locate the DMG and run the same verification as CI:

```sh
dmg_file=$(find src-tauri/target/release/bundle/dmg -maxdepth 1 -type f -name '*.dmg' -print -quit)
KEYNOXIS_REQUIRE_DISTRIBUTION_SIGNATURE=1 \
  bash scripts/verify-macos-release.sh \
  src-tauri/target/release/bundle/macos/Keynoxis.app \
  "$dmg_file"
```

For a normal unsigned local build, explicitly request an ad-hoc identity for that
single command; never restore it in `tauri.conf.json`:

```sh
APPLE_SIGNING_IDENTITY=- npm run release:macos
```

## 8. Manual notarization fallback

Apple ID credentials can be stored in the local Keychain rather than exported in
the shell:

```sh
xcrun notarytool store-credentials keynoxis-notary \
  --apple-id 'you@example.com' \
  --team-id 'TEAMID' \
  --password 'APP_SPECIFIC_PASSWORD'
```

For an already Developer ID-signed DMG:

```sh
xcrun notarytool submit /absolute/path/Keynoxis.dmg \
  --keychain-profile keynoxis-notary \
  --wait
xcrun stapler staple /absolute/path/Keynoxis.dmg
xcrun stapler validate /absolute/path/Keynoxis.dmg
```

Always inspect the notarization log if Apple returns `Invalid`:

```sh
xcrun notarytool log SUBMISSION_ID \
  --keychain-profile keynoxis-notary \
  notarization-log.json
```

## 9. Should the personal Mac be a self-hosted runner?

Usually no. The GitHub-hosted `macos-26` runner is arm64, isolated per job, and
supports the required Xcode and SDK. It is safer and requires no always-on Mac.

Use a self-hosted runner only when a release depends on local hardware, licensed
tools, or credentials that policy forbids uploading to GitHub. In that case use a
dedicated Mac and dedicated user account, restrict the runner to the repository,
keep the `release` approval gate, and never run untrusted pull requests on it.

## Official references

- [Apple: Developer ID certificates](https://developer.apple.com/help/account/certificates/create-developer-id-certificates/)
- [Apple: Notarizing macOS software](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
- [Apple: Custom notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow)
- [Tauri: macOS code signing and notarization](https://v2.tauri.app/distribute/sign/macos/)
- [GitHub: GitHub-hosted runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
- [GitHub: Deployment environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
