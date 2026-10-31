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

### Removed
- Committed build artifacts (`node_modules/`, `out/`, the `.vsix`, and a macOS-only analyzer binary).

## [0.2.0]
- Tree-sitter AST parsing and Random Forest classifier in a Go analyzer.
