import * as vscode from 'vscode';

export interface IssueCounts {
    high: number;
    medium: number;
    low: number;
}

type State =
    | { kind: 'idle'; counts: IssueCounts }
    | { kind: 'scanning' }
    | { kind: 'error'; message: string }
    | { kind: 'disabled' };

export class SentraStatusBar implements vscode.Disposable {
    private readonly item: vscode.StatusBarItem;
    private state: State = { kind: 'idle', counts: { high: 0, medium: 0, low: 0 } };
    private visible = true;

    constructor() {
        this.item = vscode.window.createStatusBarItem(
            'sentra.status',
            vscode.StatusBarAlignment.Left,
            100,
        );
        this.item.name = 'Sentra';
        this.render();
    }

    setVisible(visible: boolean): void {
        this.visible = visible;
        this.render();
    }

    setIssues(counts: IssueCounts): void {
        this.state = { kind: 'idle', counts };
        this.render();
    }

    setScanning(): void {
        this.state = { kind: 'scanning' };
        this.render();
    }

    setError(message: string): void {
        this.state = { kind: 'error', message };
        this.render();
    }

    setDisabled(): void {
        this.state = { kind: 'disabled' };
        this.render();
    }

    get isError(): boolean {
        return this.state.kind === 'error';
    }

    private render(): void {
        const s = this.state;
        this.item.backgroundColor = undefined;
        this.item.command = 'sentra.scanWorkspace';
        switch (s.kind) {
            case 'scanning':
                this.item.text = '$(sync~spin) Sentra';
                this.item.tooltip = 'Sentra: scanning…';
                break;
            case 'disabled':
                this.item.text = '$(circle-slash) Sentra';
                this.item.tooltip = 'Sentra is disabled (sentra.enabled)';
                this.item.command = undefined;
                break;
            case 'error':
                this.item.text = '$(error) Sentra';
                this.item.tooltip = `Sentra analyzer error: ${s.message}\nClick to view the log.`;
                this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
                this.item.command = 'sentra.showLog';
                break;
            case 'idle': {
                const { high, medium, low } = s.counts;
                const total = high + medium + low;
                if (total === 0) {
                    this.item.text = '$(shield) Sentra: Clean';
                    this.item.tooltip = 'No security issues found. Click to scan the workspace.';
                    break;
                }
                // e.g. "Sentra: 2H · 1M", red when anything is High, yellow otherwise.
                const parts = [
                    high ? `${high}H` : '',
                    medium ? `${medium}M` : '',
                    low ? `${low}L` : '',
                ].filter(Boolean);
                this.item.text = `${high ? '$(error)' : '$(warning)'} Sentra: ${parts.join(' · ')}`;
                const lines = [`${total} security issue${total === 1 ? '' : 's'} found`];
                if (high) {
                    lines.push(`  ${high} High`);
                }
                if (medium) {
                    lines.push(`  ${medium} Medium`);
                }
                if (low) {
                    lines.push(`  ${low} Low`);
                }
                lines.push('', 'Click to scan the workspace and open the report.');
                this.item.tooltip = lines.join('\n');
                this.item.backgroundColor = new vscode.ThemeColor(
                    high ? 'statusBarItem.errorBackground' : 'statusBarItem.warningBackground',
                );
                break;
            }
        }
        if (this.visible) {
            this.item.show();
        } else {
            this.item.hide();
        }
    }

    dispose(): void {
        this.item.dispose();
    }
}
