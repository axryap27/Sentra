# Sentra performance

All numbers come from `scripts/benchmark.sh` (raw JSON in `benchmarks/results/`) on the
machine below, except the v0.2 baseline (`benchmarks/results/baseline-v0.2-*.txt`), which was
measured on the same machine before any optimization (see `benchmarks/README.md`).

**Machine:** Intel Xeon @ 2.10 GHz, 4 cores, 15 GB RAM, Linux 6.18 x86_64, Go 1.24.7, Node 22.
A cloud VM. Expect a modern laptop to be faster.

**Corpora (pinned):**
- **django** 5.1 (`373cb30`): 2,900 Python/JS files, 500,838 lines, 18.7 MB. Includes vendored
  minified JS.
- **OWASP Benchmark** v1.2 (`f40c618`): 2,773 Java/JS files, 286,593 lines, 11.8 MB.

## Engine (Go, files pre-loaded into memory)

`go run ./cmd/sentra-bench`: per-file latency on one thread, then the whole corpus with
`runtime.NumCPU()` workers (best of 3).

| corpus | p50 / file | p90 | p99 | max | 1 thread | 4 workers | lines/sec (4 workers) |
|---|--:|--:|--:|--:|--:|--:|--:|
| django | 0.48 ms | 5.38 ms | 35.99 ms | 194 ms | 7.63 s (65,624 lines/s) | **2.60 s** | **192,571** |
| OWASP Benchmark | 1.27 ms | 2.21 ms | 3.39 ms | 122 ms | 4.00 s (71,617 lines/s) | **1.46 s** | **195,681** |

### Before and after (same machine, same corpora)

| | v0.2 | v0.3 | change |
|---|--:|--:|--:|
| django, 1 thread | 38.7 s (12,938 lines/s) | 7.63 s (65,624 lines/s) | **5.1x faster** |
| django, p50 / p99 per file | 0.73 ms / 61.8 ms | 0.48 ms / 36.0 ms | |
| `xregexp.min.js` (one 163 KB line) | ~10 s | 0.14-0.17 s ² | quadratic -> linear |
| django, 4-worker workspace scan | 19.0-19.7 s ¹ | 2.60 s | **7.3x faster** |
| OWASP, 1 thread | 9.58 s (29,678 lines/s) | 4.00 s (71,617 lines/s) | 2.4x faster |
| OWASP, p50 / p99 per file | 2.07 ms / 5.88 ms | 1.27 ms / 3.39 ms | |

¹ v0.2 `--batch --workers 4` wall time, which also includes reading files and printing JSON.
The v0.2 harness walked 2,899 django files (it did not recognize `.mjs`/`.cjs`).
² CLI wall time for that one file, including process start (3 runs). v0.2: 9.86 s with the same command.

What changed: AST traversal with a `TreeCursor` instead of `node.Child(i)` (quadratic on wide
nodes); an ancestor-context stack instead of walking `Parent()` for every candidate; node types
classified by symbol ID instead of allocating a string per node; pattern tables lowercased once;
text copied per candidate clipped to a window (minified files were quadratic); argument analysis
and feature extraction only for candidates that can matter; pooled parsers;
`GODEBUG=cgocheck=0` for the daemon (~9% of CPU went to cgo pointer checks).

## End to end from the extension (Node -> analyzer)

`node scripts/bench-daemon.mjs`: the same round trip the extension makes. 300 files sampled
evenly from each corpus; times include JSON encoding, the pipe, and parsing the response.

| corpus | spawn per file (v0.2 design) p50 / p90 / p99 | daemon round trip p50 / p90 / p99 | workspace, daemon pipelined |
|---|--:|--:|--:|
| django | 13.16 / 19.27 / 44.33 ms | **1.28 / 7.50 / 36.90 ms** | 3.36 s (149,211 lines/s) |
| OWASP Benchmark | 13.71 / 17.08 / 20.35 ms | **2.12 / 3.36 / 9.96 ms** | 2.32 s (123,758 lines/s) |

The long-lived daemon removes ~11 ms of process start-up and model loading from every scan
(p50 13.2 ms -> 1.3 ms on django, about 10x). Scan-on-type adds a 300 ms debounce on top, so a
typical file's diagnostics update about 300 ms after you stop typing.

Not shown above: the extension's content-hash cache. An unchanged file costs one SHA-256 of
its text (or, on workspace rescans, one `stat` call when mtime and size are unchanged) and no
analyzer call at all.

## Model inference

`go test -bench Proba ./internal/engine`: **543 ns per candidate, 0 allocations** (30 trees,
4,614 nodes, `model.json` 121,647 bytes embedded in the binary). Only candidates that match a
sink are scored, so inference is a negligible share of analysis time.

## Reproduce

```bash
scripts/benchmark.sh          # clones the pinned corpora into .bench/
```
