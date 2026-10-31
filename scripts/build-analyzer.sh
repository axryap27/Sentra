#!/usr/bin/env bash
# Build the analyzer for one VS Code target into bin/<target>/.
#
#   scripts/build-analyzer.sh <target>
#
# target: linux-x64 | linux-arm64 | win32-x64 | darwin-arm64 | darwin-x64 | local
#
# tree-sitter is C, so every build needs cgo and a C toolchain for the target:
#   linux-*, win32-x64   zig cc (a single hermetic cross toolchain; Linux builds are
#                        static musl binaries that run on any distro, no glibc version pin)
#   darwin-*             Apple clang on a macOS host (-arch arm64 / -arch x86_64), because
#                        linking Mach-O binaries needs the macOS SDK
# Set ZIG to override the zig command (default: zig, else python -m ziglang).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:?usage: build-analyzer.sh <target>}"
OUT="$ROOT/bin/$TARGET"
EXE=sentra-analyzer

zigcc() {
  local zig="${ZIG:-}"
  if [ -z "$zig" ]; then
    if command -v zig >/dev/null; then zig=zig; else zig="python3 -m ziglang"; fi
  fi
  local wrapper; wrapper="$(mktemp -d)/cc"
  printf '#!/bin/sh\nexec %s cc -target %s "$@"\n' "$zig" "$1" > "$wrapper"
  chmod +x "$wrapper"
  echo "$wrapper"
}

case "$TARGET" in
  linux-x64)    export GOOS=linux   GOARCH=amd64 CC="$(zigcc x86_64-linux-musl)" ;;
  linux-arm64)  export GOOS=linux   GOARCH=arm64 CC="$(zigcc aarch64-linux-musl)" ;;
  win32-x64)    export GOOS=windows GOARCH=amd64 CC="$(zigcc x86_64-windows-gnu)"; EXE=sentra-analyzer.exe ;;
  darwin-arm64) export GOOS=darwin  GOARCH=arm64 CC="clang -arch arm64" MACOSX_DEPLOYMENT_TARGET=11.0 ;;
  darwin-x64)   export GOOS=darwin  GOARCH=amd64 CC="clang -arch x86_64" MACOSX_DEPLOYMENT_TARGET=10.15 ;;
  local)        ;;
  *) echo "unknown target $TARGET" >&2; exit 2 ;;
esac

export CGO_ENABLED=1
mkdir -p "$OUT"
LDFLAGS="-s -w"
case "$TARGET" in linux-*) LDFLAGS="$LDFLAGS -linkmode external -extldflags '-static -s'" ;; esac
(cd "$ROOT/analyzer-go" && go build -trimpath -ldflags="$LDFLAGS" -o "$OUT/$EXE" .)
echo "built $OUT/$EXE ($(du -h "$OUT/$EXE" | cut -f1))"
