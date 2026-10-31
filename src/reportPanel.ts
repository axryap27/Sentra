import * as vscode from 'vscode';
import { FileReport, Severity } from './types';

/**
 * Workspace report webview. Scripts are disabled and a strict CSP is set; all
 * finding text (which contains source snippets) is HTML-escaped. Colors come from
 * VS Code theme variables, so it follows light, dark and high-contrast themes.
 */
export class ReportPanel implements vscode.Disposable {
    private panel: vscode.WebviewPanel | undefined;

    show(reports: FileReport[]): void {
        if (this.panel) {
            this.panel.reveal(vscode.ViewColumn.Beside);
        } else {
            this.panel = vscode.window.createWebviewPanel(
                'sentra.report',
                'Sentra Security Report',
                vscode.ViewColumn.Beside,
                { enableScripts: false, enableCommandUris: ['vscode.open'] },
            );
            this.panel.onDidDispose(() => (this.panel = undefined));
        }
        this.panel.webview.html = renderReport(reports, this.panel.webview.cspSource);
    }

    dispose(): void {
        this.panel?.dispose();
    }
}

export function escapeHtml(s: string): string {
    return s.replace(
        /[&<>"']/g,
        (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!,
    );
}

function openCommand(uri: string, line: number): string {
    const args = [vscode.Uri.parse(uri), { selection: new vscode.Range(line - 1, 0, line - 1, 0) }];
    return `command:vscode.open?${encodeURIComponent(JSON.stringify(args))}`;
}

export function renderReport(reports: FileReport[], cspSource: string): string {
    const count = (s: Severity) =>
        reports.reduce((n, r) => n + r.findings.filter((f) => f.severity === s).length, 0);
    const high = count('High');
    const medium = count('Medium');
    const low = count('Low');
    const total = high + medium + low;

    const files = reports
        .map(
            (r) => `
<section class="file">
  <h2>${escapeHtml(r.fileName)} <span class="muted">(${r.findings.length})</span></h2>
  <ul>
    ${r.findings
        .map(
            (f) => `<li>
      <a class="line" href="${escapeHtml(openCommand(r.uri, f.line))}">L${f.line}</a>
      <span class="sev sev-${f.severity.toLowerCase()}">${f.severity}</span>
      <span class="msg">${escapeHtml(f.issue)}</span>
    </li>`,
        )
        .join('')}
  </ul>
</section>`,
        )
        .join('');

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${cspSource} 'unsafe-inline';">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sentra Security Report</title>
<style>
  body { font-family: var(--vscode-font-family); font-size: var(--vscode-font-size); color: var(--vscode-foreground); background: var(--vscode-editor-background); padding: 16px 24px; }
  h1 { font-size: 1.4em; font-weight: 600; margin: 0 0 4px; }
  h2 { font-size: 1.05em; font-weight: 600; margin: 0; padding: 8px 12px; background: var(--vscode-sideBarSectionHeader-background, transparent); border-bottom: 1px solid var(--vscode-panel-border); }
  .muted { color: var(--vscode-descriptionForeground); font-weight: normal; }
  .summary { display: flex; gap: 12px; margin: 16px 0 24px; flex-wrap: wrap; }
  .metric { border: 1px solid var(--vscode-panel-border); border-radius: 6px; padding: 10px 16px; min-width: 110px; }
  .metric b { display: block; font-size: 1.6em; }
  .file { border: 1px solid var(--vscode-panel-border); border-radius: 6px; margin-bottom: 16px; overflow: hidden; }
  ul { list-style: none; margin: 0; padding: 0; }
  li { display: flex; gap: 10px; align-items: baseline; padding: 6px 12px; border-top: 1px solid var(--vscode-panel-border); }
  li:first-child { border-top: none; }
  .line { font-family: var(--vscode-editor-font-family); color: var(--vscode-textLink-foreground); min-width: 48px; text-decoration: none; }
  .line:hover { text-decoration: underline; }
  .sev { font-size: 0.8em; font-weight: 600; padding: 1px 8px; border-radius: 10px; border: 1px solid currentColor; }
  .sev-high { color: var(--vscode-errorForeground); }
  .sev-medium { color: var(--vscode-editorWarning-foreground); }
  .sev-low { color: var(--vscode-editorInfo-foreground); }
  .msg { word-break: break-word; }
  .empty { text-align: center; padding: 48px; color: var(--vscode-descriptionForeground); }
</style>
</head>
<body>
  <h1>Sentra Security Report</h1>
  <div class="muted">${reports.length} file${reports.length === 1 ? '' : 's'} with findings</div>
  <div class="summary">
    <div class="metric"><b>${total}</b>Total</div>
    <div class="metric"><b class="sev-high">${high}</b>High</div>
    <div class="metric"><b class="sev-medium">${medium}</b>Medium</div>
    <div class="metric"><b class="sev-low">${low}</b>Low</div>
  </div>
  ${total === 0 ? '<div class="empty"><h2>No security issues found</h2><p>Nothing at or above the configured severity level.</p></div>' : files}
</body>
</html>`;
}
