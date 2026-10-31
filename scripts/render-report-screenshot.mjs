// Render the report webview (src/reportPanel.ts) with real analyzer output on test_files/
// into docs/report.png, using VS Code Dark+ theme colors. Run after `npm run compile:tests`
// and `make go-build`:  node scripts/render-report-screenshot.mjs
import { execFileSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join, resolve } from 'node:path';

const require = createRequire(import.meta.url);
const root = resolve(import.meta.dirname, '..');
// reportPanel imports `vscode` only for the panel class and openCommand; stub the bits renderReport touches.
const Module = require('node:module');
const origLoad = Module._load;
Module._load = function (req, ...rest) {
    if (req === 'vscode') {
        return { Uri: { parse: (s) => s }, Range: class { constructor(...a) { this.a = a; } } };
    }
    return origLoad.call(this, req, ...rest);
};
const { renderReport } = require(join(root, 'out', 'reportPanel.js'));

const bin = join(root, 'bin', 'local', 'sentra-analyzer');
const files = readdirSync(join(root, 'test_files')).filter((f) => !f.startsWith('benchmark')).sort();
const reports = files.map((f) => ({
    fileName: `test_files/${f}`,
    uri: `file:///test_files/${f}`,
    findings: JSON.parse(execFileSync(bin, ['--file', join(root, 'test_files', f)]).toString()),
})).filter((r) => r.findings.length);

const theme = `:root, body {
  --vscode-font-family: -apple-system, "Segoe UI", Ubuntu, sans-serif; --vscode-font-size: 13px;
  --vscode-editor-font-family: Menlo, Consolas, monospace;
  --vscode-foreground: #cccccc; --vscode-editor-background: #1e1e1e; --vscode-panel-border: #3c3c3c;
  --vscode-descriptionForeground: #9d9d9d; --vscode-textLink-foreground: #3794ff;
  --vscode-sideBarSectionHeader-background: #252526; --vscode-errorForeground: #f48771;
  --vscode-editorWarning-foreground: #cca700; --vscode-editorInfo-foreground: #3794ff; }`;
const html = renderReport(reports, '').replace('<style>', `<style>${theme}`);

const { chromium } = require('playwright');
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1100, height: 900 }, deviceScaleFactor: 2 });
await page.setContent(html);
await page.screenshot({ path: join(root, 'docs', 'report.png'), fullPage: true });
await browser.close();
console.log('wrote docs/report.png');
