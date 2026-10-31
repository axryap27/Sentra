#!/usr/bin/env bash
# Reproduce the numbers in BENCHMARKS.md.
#
#   scripts/benchmark.sh [workdir]
#
# Clones the pinned corpora, builds the analyzer, and writes JSON results to
# benchmarks/results/. Requires go, node, git.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${1:-$ROOT/.bench}"
OUT="$ROOT/benchmarks/results"
mkdir -p "$WORK" "$OUT"

clone() { # name url commit
  if [ ! -d "$WORK/$1" ]; then
    git clone -q --filter=blob:none --no-checkout "$2" "$WORK/$1"
    git -C "$WORK/$1" checkout -q "$3"
  fi
}
clone django https://github.com/django/django.git 373cb3037fe4e67adbac9ac43340391e859aa957          # tag 5.1
clone owasp-benchmark https://github.com/OWASP-Benchmark/BenchmarkJava.git f40c618c5a709afce350ef06ed2899c85cf586e9

(cd "$ROOT/analyzer-go" && CGO_ENABLED=1 go build -trimpath -o "$ROOT/bin/local/sentra-analyzer" .)
export GODEBUG=cgocheck=0  # same as the extension sets for the daemon

{
  echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "commit: $(git -C "$ROOT" rev-parse --short HEAD)"
  echo "cpu: $(lscpu 2>/dev/null | sed -n 's/^Model name: *//p' || sysctl -n machdep.cpu.brand_string)"
  echo "cores: $(getconf _NPROCESSORS_ONLN)"
  echo "mem: $(free -g 2>/dev/null | awk '/Mem:/{print $2" GB"}')"
  echo "os: $(uname -srm)"
  echo "go: $(cd "$ROOT/analyzer-go" && go version)"
  echo "node: $(node --version)"
} | tee "$OUT/machine.txt"

for c in django owasp-benchmark; do
  (cd "$ROOT/analyzer-go" && go run ./cmd/sentra-bench -corpus "$WORK/$c" -runs 3 -json "$OUT/engine-$c.json")
  node "$ROOT/scripts/bench-daemon.mjs" "$ROOT/bin/local/sentra-analyzer" "$WORK/$c" --sample 300 | tee "$OUT/daemon-$c.json"
done
