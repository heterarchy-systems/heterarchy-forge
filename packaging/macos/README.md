# macOS local package

`cargo xtask package` builds the release desktop binary and produces a local
Installer package under `target/dist/`.

The current checked artifact target is macOS 11 or later on the host
architecture. The default developer machine currently produces arm64 output.
`cloudflared` must be available on the packaging host's `PATH`; the packaging
task copies it into `Heterarchy Forge.app/Contents/MacOS/cloudflared`, signs it
with the app payload, and verifies the helper survives the Installer archive
byte-for-byte. Installed FORGE therefore does not depend on a separate
Homebrew `cloudflared` at runtime.

The default build is intentionally local-development scoped:

- the `.app` receives an ad-hoc code signature;
- the `.pkg` is unsigned;
- the payload installs `Heterarchy Forge.app` into `/Applications`;
- the component policy disables bundle relocation, so an existing development
  build elsewhere on disk cannot redirect the installation away from
  `/Applications`;
- Developer ID signing and notarization are not implied.

Optional signing identities can be supplied without storing them in the
repository:

```sh
FORGE_APP_SIGNING_IDENTITY="Developer ID Application: Example (TEAMID)" \
FORGE_INSTALLER_SIGNING_IDENTITY="Developer ID Installer: Example (TEAMID)" \
cargo xtask package
```

The packaging task verifies the app and bundled `cloudflared` signatures,
expands the generated package, checks the exact application payload and helper
hashes, and runs the bundled executable's read-only `--doctor` entrypoint with
isolated local state. The two outputs are:

```text
target/dist/Heterarchy-Forge-<version>-<architecture>.pkg
target/dist/Heterarchy-Forge.pkg
```

Open either package in Finder to install `Heterarchy Forge.app` into
`/Applications`. Building the package does not alter `/Applications`, user
Workspace state, the global registry, or Keychain state.

## GitHub release packaging

`.github/workflows/release.yml` runs on the standard `macos-15` arm64 runner. It
installs Rust 1.92.0, downloads the pinned `cloudflared` 2026.6.1 Darwin arm64
archive, verifies the checked SHA-256, runs `make ci`, runs `cargo xtask package`,
and publishes the versioned `.pkg` plus `SHA256SUMS.txt` to the matching GitHub
Release. The pushed tag must exactly equal `v<workspace version>`.

No signing identity or signing material is stored in the repository. The current
workflow therefore publishes the same ad-hoc app-signed, unsigned Installer
package described above. Production-quality public distribution still requires
Developer ID app/installer signing and Apple notarization before the Release is
published.
