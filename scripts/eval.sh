#!/usr/bin/env bash
# Reproduce EVAL.md: split OWASP Benchmark, dump train features, retrain, evaluate.
#
#   scripts/eval.sh [workdir]
#
# Requires go, python3 with analyzer-go/training/requirements.txt installed.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${1:-$ROOT/.bench}"
OWASP="$WORK/owasp-benchmark"
mkdir -p "$WORK"
if [ ! -d "$OWASP" ]; then
  git clone -q --filter=blob:none --no-checkout https://github.com/OWASP-Benchmark/BenchmarkJava.git "$OWASP"
  git -C "$OWASP" checkout -q f40c618c5a709afce350ef06ed2899c85cf586e9
fi

cd "$ROOT/analyzer-go"
python3 eval/owasp_split.py "$OWASP" > eval/owasp_split.json
python3 training/generate_dataset.py
go run ./cmd/sentra-eval -owasp "$OWASP" -subset train -no-model -dump training/owasp_train_features.jsonl > /dev/null
python3 training/train_model.py
go run ./cmd/sentra-eval -owasp "$OWASP" -subset test -no-model -json eval/results-v0.3-gates-test.json
go run ./cmd/sentra-eval -owasp "$OWASP" -subset test -json eval/results-v0.3-test.json -curve eval/curve-v0.3-test.json
python3 eval/render_tables.py
