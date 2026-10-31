import * as vscode from 'vscode';

type State =
    | { kind: 'idle'; issues: number }
    | { kind: 'scanning' }
    | { kind: 'error'; message: string }
    | { kind: 'disabled' };

export class SentraStatusBar implements vscode.Disposable {
    private readonly item: vscode.StatusBarItem;
    private state: State = { kind: 'idle', issues: 0 };
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

    setIssues(issues: number): void {
        this.state = { kind: 'idle', issues };
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
            case 'idle':
                if (s.issues === 0) {
                    this.item.text = '$(shield) Sentra';
                    this.item.tooltip = 'No security issues found. Click to scan the workspace.';
                } else {
                    this.item.text = `$(alert) Sentra: ${s.issues}`;
                    this.item.tooltip = `${s.issues} security issue${s.issues === 1 ? '' : 's'} found. Click to scan the workspace.`;
                    this.item.backgroundColor = new vscode.ThemeColor(
                        'statusBarItem.warningBackground',
                    );
                }
                break;
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
