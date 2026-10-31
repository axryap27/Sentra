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

### Removed
- Committed build artifacts (`node_modules/`, `out/`, the `.vsix`, and a macOS-only analyzer binary).

## [0.2.0]
- Tree-sitter AST parsing and Random Forest classifier in a Go analyzer.
