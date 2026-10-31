#!/usr/bin/env bash
# Package a platform-specific VSIX containing only that platform's analyzer.
#
#   scripts/package.sh <target> [binaries-dir]
#
# Expects <binaries-dir>/<target>/sentra-analyzer[.exe] (default: bin/). Writes
# dist-vsix/sentra-<target>-<version>.vsix.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:?usage: package.sh <target> [binaries-dir]}"
SRC="${2:-$ROOT/bin}"
cd "$ROOT"

STAGE="$(mktemp -d)"
cp -R "$SRC/$TARGET" "$STAGE/$TARGET"
# .vscodeignore ships bin/**, so bin/ must hold exactly this target while packaging.
if [ -d bin ]; then mv bin "$STAGE/bin.saved"; fi
restore() { rm -rf bin; if [ -d "$STAGE/bin.saved" ]; then mv "$STAGE/bin.saved" bin; fi; rm -rf "$STAGE"; }
trap restore EXIT
mkdir -p bin && cp -R "$STAGE/$TARGET" "bin/$TARGET"
chmod +x bin/"$TARGET"/sentra-analyzer* || true

VERSION="$(node -p 'require("./package.json").version')"
mkdir -p dist-vsix
npx vsce package --target "$TARGET" --out "dist-vsix/sentra-$TARGET-$VERSION.vsix"
