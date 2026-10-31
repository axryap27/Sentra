import { randomBytes } from 'crypto';
import * as vscode from 'vscode';
import { cweUrl, ruleInfo } from './rules';
import { FileReport, SEVERITY_RANK, Severity } from './types';

/**
 * Workspace report webview: security score, severity cards and tabs that filter the
 * list, and collapsible per-file sections.
 *
 * Security: every piece of finding text (which contains source snippets) is
 * HTML-escaped; the only script is a fixed block authorized by a per-render nonce
 * under a strict CSP (no inline event handlers, no remote content). Colors come from
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
                { enableScripts: true, enableCommandUris: ['vscode.open'], localResourceRoots: [] },
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

/**
 * A heuristic 0-100 summary for the dashboard: 100 minus 15 per High, 5 per Medium and
 * 1 per Low finding. It is a UI indicator, not a measured risk score.
 */
export function securityScore(high: number, medium: number, low: number): number {
    return Math.max(0, Math.min(100, 100 - high * 15 - medium * 5 - low));
}

export function renderReport(
    reports: FileReport[],
    cspSource: string,
    now: Date = new Date(),
    nonce: string = randomBytes(16).toString('base64'),
): string {
    const count = (s: Severity) =>
        reports.reduce((n, r) => n + r.findings.filter((f) => f.severity === s).length, 0);
    const high = count('High');
    const medium = count('Medium');
    const low = count('Low');
    const total = high + medium + low;

    const score = securityScore(high, medium, low);
    const scoreClass = score >= 80 ? 'good' : score >= 50 ? 'warn' : 'bad';
    const radius = 54;
    const circumference = 2 * Math.PI * radius;
    const dashOffset = circumference - (score / 100) * circumference;
    const time = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const plural = (n: number, w: string) => `${n} ${w}${n === 1 ? '' : 's'}`;

    const files = reports
        .map((r, i) => {
            const h = r.findings.filter((f) => f.severity === 'High').length;
            const m = r.findings.filter((f) => f.severity === 'Medium').length;
            const l = r.findings.filter((f) => f.severity === 'Low').length;
            const slash = r.fileName.lastIndexOf('/');
            const name = r.fileName.slice(slash + 1);
            const dir = slash >= 0 ? r.fileName.slice(0, slash + 1) : '';
            const rows = [...r.findings]
                .sort(
                    (a, b) =>
                        SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.line - b.line,
                )
                .map((f) => {
                    const sev = f.severity.toLowerCase();
                    const cwe = f.cwe
                        ? `<a class="cwe" href="${escapeHtml(cweUrl(f.cwe))}" title="${escapeHtml(ruleInfo(f.rule)?.title ?? f.cwe)}">${escapeHtml(f.cwe)}</a>`
                        : '';
                    return `
      <div class="issue" data-sev="${f.severity}">
        <div class="accent accent-${sev}"></div>
        <div class="issue-content">
          <div class="issue-top">
            <a class="line-badge" href="${escapeHtml(openCommand(r.uri, f.line))}" title="Go to line">L${f.line}</a>
            <span class="pill pill-${sev}">${f.severity}</span>
            ${cwe}
          </div>
          <div class="issue-desc">${escapeHtml(f.issue)}</div>
        </div>
      </div>`;
                })
                .join('');
            return `
  <div class="file-card">
    <button class="file-header" data-file="${i}" aria-expanded="true">
      <span class="file-left">
        <span class="chevron open">▶</span>
        <span class="file-name">${escapeHtml(name)}</span>
        ${dir ? `<span class="file-dir">${escapeHtml(dir)}</span>` : ''}
      </span>
      <span class="file-badges">
        ${h ? `<span class="mini mini-high">${h} high</span>` : ''}
        ${m ? `<span class="mini mini-medium">${m} med</span>` : ''}
        ${l ? `<span class="mini mini-low">${l} low</span>` : ''}
      </span>
    </button>
    <div class="file-body open" id="fb${i}">${rows}
    </div>
  </div>`;
        })
        .join('');

    const statCard = (filter: string, label: string, n: number, cls: string, active = false) => `
    <button class="stat-card${active ? ' active' : ''}" data-filter="${filter}">
      <span class="dot dot-${cls}"></span>
      <span><span class="stat-count c-${cls}">${n}</span><span class="stat-name">${label}</span></span>
    </button>`;

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${cspSource} 'unsafe-inline'; script-src 'nonce-${nonce}';">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sentra Security Report</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --high: var(--vscode-charts-red, #f85149);
    --medium: var(--vscode-charts-yellow, #d29922);
    --low: var(--vscode-charts-blue, #3794ff);
    --good: var(--vscode-charts-green, #3fb950);
    --card: var(--vscode-sideBar-background, transparent);
    --border: var(--vscode-panel-border, rgba(128,128,128,.35));
    --muted: var(--vscode-descriptionForeground);
  }
  body { font-family: var(--vscode-font-family); font-size: 13px; color: var(--vscode-foreground);
         background: var(--vscode-editor-background); padding: 24px; }
  button { font: inherit; color: inherit; background: none; border: none; text-align: left; cursor: pointer; }
  button:focus-visible { outline: 1px solid var(--vscode-focusBorder); outline-offset: 2px; }

  .header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 24px; gap: 12px; }
  .brand { display: flex; align-items: center; gap: 10px; }
  .brand-name { font-size: 18px; font-weight: 700; letter-spacing: -0.3px; }
  .brand-sub, .meta { font-size: 11px; color: var(--muted); }
  .meta { text-align: right; }

  .top-row { display: flex; gap: 16px; margin-bottom: 24px; align-items: stretch; flex-wrap: wrap; }
  .score-card { display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 8px;
                padding: 20px 28px; border: 1px solid var(--border); border-radius: 10px; background: var(--card); min-width: 160px; }
  .ring { position: relative; width: 120px; height: 120px; }
  .ring svg { transform: rotate(-90deg); }
  .ring .track { fill: none; stroke: var(--border); stroke-width: 8; }
  .ring .fill { fill: none; stroke-width: 8; stroke-linecap: round; }
  .ring-value { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; }
  .score-number { font-size: 28px; font-weight: 700; line-height: 1; }
  .score-label, .score-title { font-size: 11px; color: var(--muted); }
  .good { color: var(--good); stroke: var(--good); }
  .warn { color: var(--medium); stroke: var(--medium); }
  .bad { color: var(--high); stroke: var(--high); }

  .stats { display: grid; grid-template-columns: repeat(2, minmax(140px, 1fr)); gap: 12px; flex: 1; }
  .stat-card { display: flex; align-items: center; gap: 14px; padding: 14px 16px; border: 1px solid var(--border);
               border-radius: 10px; background: var(--card); transition: border-color .15s; }
  .stat-card:hover, .stat-card.active { border-color: var(--vscode-focusBorder); }
  .stat-card.active { background: var(--vscode-list-inactiveSelectionBackground, var(--card)); }
  .dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
  .dot-total { background: var(--vscode-foreground); opacity: .5; }
  .dot-high { background: var(--high); } .dot-medium { background: var(--medium); } .dot-low { background: var(--low); }
  .stat-count { display: block; font-size: 26px; font-weight: 700; line-height: 1; }
  .stat-name { display: block; font-size: 11px; color: var(--muted); margin-top: 2px; }
  .c-high { color: var(--high); } .c-medium { color: var(--medium); } .c-low { color: var(--low); }

  .filter-bar { display: flex; align-items: center; justify-content: space-between; margin-bottom: 14px; }
  .tabs { display: flex; gap: 4px; }
  .tab { padding: 4px 12px; border-radius: 6px; font-size: 12px; font-weight: 500; border: 1px solid transparent; color: var(--muted); }
  .tab:hover { color: var(--vscode-foreground); border-color: var(--border); }
  .tab.active { color: var(--vscode-foreground); border-color: var(--vscode-focusBorder);
                background: var(--vscode-list-inactiveSelectionBackground, transparent); }
  .count { font-size: 11px; color: var(--muted); }

  .file-card { border: 1px solid var(--border); border-radius: 10px; margin-bottom: 12px; overflow: hidden; }
  .file-header { width: 100%; display: flex; align-items: center; justify-content: space-between; gap: 8px;
                 padding: 10px 14px; background: var(--card); user-select: none; }
  .file-left { display: flex; align-items: center; gap: 8px; min-width: 0; }
  .chevron { font-size: 10px; color: var(--muted); transition: transform .2s; }
  .chevron.open { transform: rotate(90deg); }
  .file-name { font-size: 12px; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .file-dir { font-size: 11px; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .file-badges { display: flex; gap: 4px; flex-shrink: 0; }
  .mini { padding: 2px 7px; border-radius: 10px; font-size: 10px; font-weight: 600; border: 1px solid currentColor; }
  .mini-high { color: var(--high); } .mini-medium { color: var(--medium); } .mini-low { color: var(--low); }
  .file-body { display: none; } .file-body.open { display: block; }

  .issue { display: flex; gap: 12px; padding: 10px 14px; border-top: 1px solid var(--border); }
  .issue:hover { background: var(--vscode-list-hoverBackground); }
  .accent { width: 3px; border-radius: 2px; align-self: stretch; flex-shrink: 0; min-height: 20px; }
  .accent-high { background: var(--high); } .accent-medium { background: var(--medium); } .accent-low { background: var(--low); }
  .issue-content { flex: 1; min-width: 0; }
  .issue-top { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; flex-wrap: wrap; }
  .line-badge { font-family: var(--vscode-editor-font-family); font-size: 10px; padding: 2px 6px; border-radius: 4px;
                background: var(--vscode-badge-background); color: var(--vscode-badge-foreground); text-decoration: none; }
  .pill { font-size: 9px; font-weight: 700; padding: 2px 7px; border-radius: 10px; text-transform: uppercase;
          letter-spacing: .4px; border: 1px solid currentColor; }
  .pill-high { color: var(--high); } .pill-medium { color: var(--medium); } .pill-low { color: var(--low); }
  .cwe { font-size: 11px; color: var(--vscode-textLink-foreground); margin-left: auto; }
  .issue-desc { font-size: 12px; line-height: 1.5; word-break: break-word; }

  .empty { display: flex; flex-direction: column; align-items: center; padding: 80px 24px; text-align: center; gap: 12px; }
  .empty-title { font-size: 16px; font-weight: 600; }
  .empty-sub { font-size: 12px; color: var(--muted); max-width: 320px; line-height: 1.6; }
  .hidden { display: none !important; }
</style>
</head>
<body>
<div class="header">
  <div class="brand">
    <svg class="${scoreClass}" width="28" height="28" viewBox="0 0 28 28" fill="none" aria-hidden="true">
      <path d="M14 2L4 6.5V14C4 19.5 8.5 24.5 14 26C19.5 24.5 24 19.5 24 14V6.5L14 2Z" fill="currentColor" fill-opacity="0.15" stroke="currentColor" stroke-width="1.5"/>
      <path d="M10 14l3 3 5-5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
    <div><div class="brand-name">Sentra</div><div class="brand-sub">Security Analysis</div></div>
  </div>
  <div class="meta">${plural(reports.length, 'file')} with findings · ${escapeHtml(time)}</div>
</div>

<div class="top-row">
  <div class="score-card" title="100 − 15 per High − 5 per Medium − 1 per Low finding">
    <div class="ring">
      <svg width="120" height="120" viewBox="0 0 120 120" aria-hidden="true">
        <circle class="track" cx="60" cy="60" r="${radius}"/>
        <circle class="fill ${scoreClass}" cx="60" cy="60" r="${radius}" stroke-dasharray="${circumference.toFixed(2)}" stroke-dashoffset="${dashOffset.toFixed(2)}"/>
      </svg>
      <div class="ring-value"><span class="score-number ${scoreClass}" id="scoreNum" data-score="${score}">${score}</span><span class="score-label">/ 100</span></div>
    </div>
    <div class="score-title">Security Score</div>
  </div>
  <div class="stats">
    ${statCard('all', 'Total Issues', total, 'total', true)}
    ${statCard('High', 'High Severity', high, 'high')}
    ${statCard('Medium', 'Medium Severity', medium, 'medium')}
    ${statCard('Low', 'Low Severity', low, 'low')}
  </div>
</div>

${
    total === 0
        ? `<div class="empty"><div class="empty-title">All clear</div><div class="empty-sub">No issues at or above the configured severity level.</div></div>`
        : `<div class="filter-bar">
  <div class="tabs">
    <button class="tab active" data-filter="all">All</button>
    <button class="tab" data-filter="High">High</button>
    <button class="tab" data-filter="Medium">Medium</button>
    <button class="tab" data-filter="Low">Low</button>
  </div>
  <span class="count" id="resultsCount">${plural(total, 'issue')}</span>
</div>
<div id="content">${files}
</div>`
}

<script nonce="${nonce}">
  (function () {
    var num = document.getElementById('scoreNum');
    var target = Number(num.dataset.score), cur = 0;
    num.textContent = '0';
    (function step() { if (cur < target) { cur = Math.min(target, cur + 2); num.textContent = String(cur); requestAnimationFrame(step); } else { num.textContent = String(target); } })();

    function setFilter(f) {
      document.querySelectorAll('[data-filter]').forEach(function (el) { el.classList.toggle('active', el.dataset.filter === f); });
      var visible = 0;
      document.querySelectorAll('.file-card').forEach(function (card) {
        var shown = 0;
        card.querySelectorAll('.issue').forEach(function (row) {
          var show = f === 'all' || row.dataset.sev === f;
          row.classList.toggle('hidden', !show);
          if (show) shown++;
        });
        card.classList.toggle('hidden', shown === 0);
        visible += shown;
      });
      var rc = document.getElementById('resultsCount');
      if (rc) rc.textContent = visible + ' issue' + (visible === 1 ? '' : 's');
    }
    document.querySelectorAll('[data-filter]').forEach(function (el) {
      el.addEventListener('click', function () { setFilter(el.dataset.filter); });
    });
    document.querySelectorAll('.file-header').forEach(function (h) {
      h.addEventListener('click', function () {
        var body = document.getElementById('fb' + h.dataset.file);
        var open = body.classList.toggle('open');
        h.querySelector('.chevron').classList.toggle('open', open);
        h.setAttribute('aria-expanded', String(open));
      });
    });
  })();
</script>
</body>
</html>`;
}
