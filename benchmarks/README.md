# Benchmarks

`results/baseline-v0.2-*.txt` are measurements of the v0.2.0 engine (commit `ccab77a`)
taken before any optimization, with a throwaway serial harness equivalent to
`cmd/sentra-bench`'s serial pass (files pre-read into memory, one thread). The v0.2
`--batch --workers 4` wall time on django was 19.0–19.7 s (3 runs).

Everything else in `results/` is produced by `scripts/benchmark.sh`.
