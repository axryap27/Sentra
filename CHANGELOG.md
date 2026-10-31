# Changelog

All notable changes to Sentra are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- **Breaking:** command and setting IDs renamed from `secureCodeAnalyzer.*` to `sentra.*`.
  Re-apply any customized settings under the new names.
- Removed the unused `pythonPath` setting.
- The extension is now bundled with esbuild (`dist/extension.js`).

### Added
- Long-lived analyzer daemon (`sentra-analyzer --serve`, newline-delimited JSON over
  stdio): the model and grammars load once, requests are pipelined and analyzed in
  parallel (`runtime.NumCPU()` workers), and the daemon is restarted on crash.
- Debounced scan-on-type (`sentra.scanOnType`, `sentra.scanOnTypeDelay`, default 300 ms).
- Workspace rescans skip files whose mtime and size are unchanged, without reading them.
- Diagnostics underline the offending expression and link to the CWE entry.
- Benchmark harness: `cmd/sentra-bench`, `scripts/bench-daemon.mjs`, `scripts/benchmark.sh`.
- Quick fixes: md5/sha1 -> sha256 (Python, Java, Node), `shell=True` -> `shlex.split(...)`
  without a shell, `yaml.load` -> `yaml.safe_load`, `Math.random()` ->
  `crypto.getRandomValues`, `strcpy`/`strcat`/`sprintf`/`gets` -> bounded variants, and
  "suppress on this line" for every finding.
- Hovers explain each finding: rule, CWE link, severity, model confidence, remediation.
- `Sentra: Export Results as SARIF` and `sentra-analyzer --batch --format sarif` produce
  SARIF 2.1.0 for GitHub code scanning (with `security-severity`).
- The report sorts by severity and links each finding's CWE.

### Packaging
- Platform-specific VSIX files for linux-x64, linux-arm64, win32-x64, darwin-arm64 and
  darwin-x64, each with a prebuilt analyzer (static musl binaries on Linux).
- GitHub Actions: CI on pull requests; tagged releases build, smoke-test on each OS,
  package and publish to the VS Code Marketplace and Open VSX. See PUBLISHING.md.

### Accuracy (see EVAL.md)
- New real-world evaluation on a held-out, file-level split of OWASP Benchmark v1.2
  (981 Java cases): precision 0.486 -> 0.718, recall 0.172 -> 0.776, FPR 0.190 -> 0.319,
  OWASP score -0.018 -> +0.458.
- Light intra-procedural taint tracking (user input, parameters, concatenation, constants)
  and five new dataflow features.
- Language-scoped sink table with new Java servlet, JDBC/Spring, file and randomness sinks.
- Deterministic precision gates (weak algorithm literals, constant arguments, `regex.exec`,
  `free()`, `yaml.load(..., SafeLoader)`, ...).
- The Random Forest now gates findings with per-rule probability thresholds tuned for
  F0.5 on out-of-fold train data (Java only), instead of only labeling confidence.
- Hardcoded-secret detection requires a string literal and understands identifier words
  and known credential formats (AWS, GitHub, Slack, OpenAI, Google, private keys).
- Inline suppressions: `sentra-ignore`, `sentra-ignore: rule1, rule2`, `sentra-ignore-file`.

### Performance
- Serial analysis of django 5.1 (2,899 files, 501k lines) went from 38.7 s to 8.2 s,
  and the 4-worker workspace scan from 19.0 s to 2.8 s. See BENCHMARKS.md.
  - Minified files no longer cost quadratic time (one 163 KB line took ~10 s).
  - AST walk uses a TreeCursor and an ancestor-context stack instead of
    `Child(i)` loops and repeated `Parent()` walks.
  - Pattern tables are lowercased once; node types are classified by symbol ID.

### Fixed
- **Security:** the analyzer was launched with `child_process.exec` and an interpolated
  command string (shell command injection via file paths). It is now spawned directly
  with an argv array, and no shell is involved anywhere.
- **Security:** the report webview rendered unescaped finding text (which contains
  source snippets) with scripts enabled. Text is now escaped, scripts are disabled and
  a strict CSP is set.
- Source is sent to the analyzer over stdin; no temp file is written per scan.
- The extension no longer runs `go build` at runtime; it uses a prebuilt binary.
- Analyzer crashes, timeouts and malformed output now show an error state in the
  status bar (click it for the log) instead of failing silently.
- `excludePatterns` and `maxFileSize` now apply to open/save scans, not only workspace
  scans; `autoScan` now governs scan-on-open as well as on-save; `showStatusBar` was
  previously ignored; changing `severityLevel` re-filters existing results without a
  rescan; turning `enabled` off clears diagnostics.
- The analyzer printed `null` instead of `[]` for files with no findings.
- String-concatenation detection was confused by `'` inside `"..."` strings.
- The fallback line scanner (removed) flagged words such as "query" in docstrings.

### Removed
- Committed build artifacts (`node_modules/`, `out/`, the `.vsix`, and a macOS-only analyzer binary).

## [0.2.0]
- Tree-sitter AST parsing and Random Forest classifier in a Go analyzer.
