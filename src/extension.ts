import * as vscode from 'vscode';
import * as path from 'path';
import { SecurityAnalyzer } from './analyzer';
import { SecurityStatusBar } from './statusBar';
import { SecurityReportPanel } from './webviewPanel';

let analyzer: SecurityAnalyzer;
let statusBar: SecurityStatusBar;
let reportPanel: SecurityReportPanel;

export function activate(context: vscode.ExtensionContext) {
    console.log('Sentra extension is now active');

    // Initialize components
    analyzer = new SecurityAnalyzer(context);
    statusBar = new SecurityStatusBar();
    reportPanel = new SecurityReportPanel(context);

    // Register commands
    const scanFileCommand = vscode.commands.registerCommand('sentra.scanFile', async (uri?: vscode.Uri) => {
        const targetUri = uri || vscode.window.activeTextEditor?.document.uri;
        if (targetUri) {
            await analyzer.scanFile(targetUri);
        } else {
            vscode.window.showWarningMessage('No file selected for scanning');
        }
    });

    const scanWorkspaceCommand = vscode.commands.registerCommand('sentra.scanWorkspace', async () => {
        const reports = await analyzer.scanWorkspace();
        if (reports) {
            reportPanel.showReport(reports);
            const totalIssues = reports.reduce((sum, report) => sum + report.issues.length, 0);
            statusBar.updateIssueCount(totalIssues);
        }
    });

    const showReportCommand = vscode.commands.registerCommand('sentra.showReport', async () => {
        const reports = await analyzer.getLastWorkspaceReport();
        if (reports) {
            reportPanel.showReport(reports);
        } else {
            vscode.window.showInformationMessage('No security report available. Run a workspace scan first.');
        }
    });

    const clearDiagnosticsCommand = vscode.commands.registerCommand('sentra.clearDiagnostics', () => {
        analyzer.clearAllDiagnostics();
    });

    // Register file save listener for auto-scan
    const onSaveDisposable = vscode.workspace.onDidSaveTextDocument(async (document) => {
        const config = vscode.workspace.getConfiguration('sentra');
        const supportedLanguages = ['python', 'javascript', 'typescript', 'java', 'c', 'cpp', 'go', 'php', 'csharp', 'rust'];
        if (config.get('autoScan') && config.get('enabled') && supportedLanguages.includes(document.languageId)) {
            await analyzer.scanFile(document.uri);
        }
    });

    // Register file open listener
    const onOpenDisposable = vscode.workspace.onDidOpenTextDocument(async (document) => {
        const config = vscode.workspace.getConfiguration('sentra');
        const supportedLanguages = ['python', 'javascript', 'typescript', 'java', 'c', 'cpp', 'go', 'php', 'csharp', 'rust'];
        if (config.get('enabled') && supportedLanguages.includes(document.languageId)) {
            await analyzer.scanFile(document.uri);
        }
    });

    // Add to context subscriptions
    context.subscriptions.push(
        scanFileCommand,
        scanWorkspaceCommand,
        showReportCommand,
        clearDiagnosticsCommand,
        onSaveDisposable,
        onOpenDisposable,
        statusBar
    );

    // Show activation message
    vscode.window.showInformationMessage('Sentra is ready!');
}

export function deactivate() {
    if (analyzer) {
        analyzer.dispose();
    }
    if (statusBar) {
        statusBar.dispose();
    }
    if (reportPanel) {
        reportPanel.dispose();
    }
}