# Publishing Sentra

Releases are automated by `.github/workflows/release.yml`: pushing a `v*` tag builds the
analyzer for every platform, smoke-tests each binary on its own OS, packages one VSIX per
platform, and publishes them to the VS Code Marketplace and Open VSX. The account setup below
has to be done once, by hand, by the publisher.

## One-time setup

### 1. Pick the publisher ID

`package.json` has `"publisher": "aaryapatel"`. The ID is permanent and becomes part of the
extension ID (`aaryapatel.sentra`) and the Marketplace URL. Change it in `package.json` now if you
want a different one, and use the same ID in steps 2 and 4. (The integration tests activate the
extension by this ID, in `src/test/integration/extension.test.ts`.)

### 2. Create the VS Code Marketplace publisher

1. Go to <https://marketplace.visualstudio.com/manage> and sign in with a Microsoft account.
2. Click **Create publisher**. Enter the ID from step 1 and a display name (e.g. "Aarya Patel").
3. Save. The publisher page is now at `https://marketplace.visualstudio.com/publishers/<id>`.

### 3. Create an Azure DevOps Personal Access Token (for `vsce`)

1. Go to <https://dev.azure.com>, sign in with **the same Microsoft account**, and create an
   organization if you have none (any name).
2. Top right, open **User settings** (person icon) → **Personal access tokens** → **New Token**.
3. Fill in:
   - **Name:** `sentra-vsce`
   - **Organization:** **All accessible organizations** (required; a single org will fail with 401)
   - **Expiration:** your choice (max 1 year; put a reminder to rotate it)
   - **Scopes:** **Custom defined** → **Show all scopes** → **Marketplace** → tick **Manage**
4. Create and copy the token (it is shown once).
5. Optional check from your machine: `npx @vscode/vsce login <publisher-id>` and paste the token.

### 4. Create the Open VSX namespace and token (for `ovsx`)

Open VSX is the registry used by VSCodium, Cursor, Gitpod, Eclipse Theia and others.

1. Sign in at <https://open-vsx.org> with GitHub.
2. Sign the Eclipse Foundation Publisher Agreement when prompted (profile → **Log in with Eclipse**,
   create an Eclipse account if needed, then sign).
3. Profile → **Access Tokens** → **Generate New Token** (description `sentra-ci`). Copy it.
4. Create the namespace once, matching the publisher ID:
   `npx ovsx create-namespace <publisher-id> -p <open-vsx-token>`

### 5. Add the repository secrets

GitHub → `axryap27/sentra` → **Settings** → **Secrets and variables** → **Actions** →
**New repository secret**:

| Name | Value |
|---|---|
| `VSCE_PAT` | the Azure DevOps token from step 3 |
| `OVSX_PAT` | the Open VSX token from step 4 |

The publish job runs in a GitHub environment named `marketplace`. GitHub creates it on first use.
If you want a manual approval before anything is published, open **Settings → Environments →
marketplace** and add yourself as a required reviewer.

## Releasing

1. Update `version` in `package.json` and `Version` in `analyzer-go/internal/engine/analyze.go`
   (the extension mixes the engine version into its cache keys).
2. Move the `[Unreleased]` notes in `CHANGELOG.md` under the new version.
3. Commit, then tag and push:

   ```bash
   git tag v0.3.0
   git push origin v0.3.0
   ```

4. Watch **Actions → Release**. It runs: build (5 targets) → smoke test on each OS → package →
   publish to the Marketplace and Open VSX → GitHub release with the VSIX files attached.

To build and test the VSIX files without publishing, run the workflow manually
(**Actions → Release → Run workflow**) with *Publish* unchecked; the VSIX files are attached to
the run as the `vsix` artifact.

## Building locally

```bash
pip install ziglang==0.13.0         # cross C toolchain for cgo (tree-sitter)
scripts/build-analyzer.sh linux-x64  # or linux-arm64, win32-x64 (any host)
scripts/build-analyzer.sh darwin-arm64  # darwin-* need a Mac (Apple clang + SDK)
npm ci && scripts/package.sh linux-x64  # -> dist-vsix/sentra-linux-x64-<version>.vsix
```

### Why this toolchain

tree-sitter grammars are C, so the analyzer must be built with cgo and a C compiler for each
target. Options considered:

- **Per-OS CI runners only:** simplest, but needs five runner types (including Linux arm64 and
  Intel macOS, which is being phased out), and Linux binaries would depend on the runner's glibc.
- **zig cc (chosen for Linux and Windows):** one hermetic cross toolchain on one Ubuntu runner.
  Linux binaries are **static musl** executables, so they run on any distribution regardless of
  glibc version; Windows binaries use MinGW-w64 from zig. Reproducible locally on any OS.
- **Apple clang (chosen for macOS):** linking Mach-O executables needs the macOS SDK, which is not
  redistributable, so both darwin targets build on a `macos-14` runner with `clang -arch arm64` /
  `-arch x86_64`.

Every binary is then executed on its own OS (including `ubuntu-24.04-arm` and Intel `macos-13`)
before anything is packaged.

## Install a VSIX by hand

```bash
code --install-extension dist-vsix/sentra-linux-x64-0.3.0.vsix
```
