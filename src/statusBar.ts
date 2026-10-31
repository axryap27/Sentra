import * as vscode from 'vscode';

export class SecurityStatusBar {
    private statusBarItem: vscode.StatusBarItem;
    private issueCount = 0;

    constructor() {
        this.statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
        this.statusBarItem.command = 'sentra.scanWorkspace';
        this.updateStatusBar();
        this.statusBarItem.show();
    }

    updateIssueCount(count: number): void {
        this.issueCount = count;
        this.updateStatusBar();
    }

    private updateStatusBar(): void {
        if (this.issueCount === 0) {
            this.statusBarItem.text = '$(shield) Security: Clean';
            this.statusBarItem.tooltip = 'No security issues found. Click to scan workspace.';
            this.statusBarItem.backgroundColor = undefined;
        } else {
            this.statusBarItem.text = `$(alert) Security: ${this.issueCount} issue${this.issueCount > 1 ? 's' : ''}`;
            this.statusBarItem.tooltip = `${this.issueCount} security issue${this.issueCount > 1 ? 's' : ''} found. Click to scan workspace.`;
            this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
        }
    }

    dispose(): void {
        this.statusBarItem.dispose();
    }
}