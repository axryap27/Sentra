import * as vscode from 'vscode';
import { AnalyzerError, findAnalyzerBinary } from './analyzerBinary';
import { AnalyzerClient } from './analyzerClient';
import { CONFIG_SECTION, getConfig } from './config';
import { ReportPanel } from './reportPanel';
import { ResultCache } from './resultCache';
import { Analyzer, Scanner } from './scanner';
import { SentraStatusBar } from './statusBar';

export function activate(context: vscode.ExtensionContext): void {
    const log = vscode.window.createOutputChannel('Sentra');
    const statusBar = new SentraStatusBar();
    const reportPanel = new ReportPanel();
    statusBar.setVisible(getConfig().showStatusBar);

    const binary = findAnalyzerBinary(context.extensionPath);
    let analyzer: Analyzer;
    if (binary) {
        analyzer = new AnalyzerClient(binary);
        log.appendLine(`Using analyzer ${binary}`);
    } else {
        const msg = `No Sentra analyzer binary for ${process.platform}-${process.arch}. Install the platform-specific build of the extension.`;
        analyzer = { analyze: () => Promise.reject(new AnalyzerError('missing-binary', msg)) };
        log.appendLine(msg);
        statusBar.setError(msg);
    }

    const engineVersion = String(context.extension.packageJSON.version ?? '0');
    const scanner = new Scanner(
        analyzer,
        new ResultCache(context.workspaceState, engineVersion),
        statusBar,
        log,
    );
    if (!getConfig().enabled) {
        statusBar.setDisabled();
    }

    const autoScan = (doc: vscode.TextDocument) => {
        if (getConfig(doc.uri).autoScan) {
            void scanner.scanDocument(doc);
        }
    };

    context.subscriptions.push(
        log,
        statusBar,
        reportPanel,
        scanner,
        vscode.commands.registerCommand('sentra.scanFile', async (uri?: vscode.Uri) => {
            const target = uri ?? vscode.window.activeTextEditor?.document.uri;
            if (!target) {
                vscode.window.showWarningMessage('Sentra: no file selected to scan.');
                return;
            }
            const reason = scanner.skipReason(target, getConfig(target));
            if (reason) {
                vscode.window.showInformationMessage(`Sentra: not scanning this file (${reason}).`);
                return;
            }
            await scanner.scanUri(target);
        }),
        vscode.commands.registerCommand('sentra.scanWorkspace', async () => {
            if (!getConfig().enabled) {
                vscode.window.showInformationMessage('Sentra is disabled (sentra.enabled).');
                return;
            }
            const result = await vscode.window.withProgress(
                {
                    location: vscode.ProgressLocation.Notification,
                    title: 'Sentra: scanning workspace',
                    cancellable: true,
                },
                (progress, token) => {
                    let last = 0;
                    return scanner.scanWorkspace(token, (done, total) => {
                        const pct = (done / total) * 100;
                        progress.report({
                            increment: pct - last,
                            message: `${done}/${total} files`,
                        });
                        last = pct;
                    });
                },
            );
            log.appendLine(
                `Workspace scan: ${result.filesScanned} files (${result.cacheHits} cached) in ${result.durationMs} ms`,
            );
            if (!statusBar.isError) {
                reportPanel.show(result.reports);
            }
        }),
        vscode.commands.registerCommand('sentra.showReport', () => {
            const reports = scanner.getLastReport();
            if (reports) {
                reportPanel.show(reports);
            } else {
                vscode.window.showInformationMessage(
                    'Sentra: no report yet. Run "Scan Workspace for Vulnerabilities" first.',
                );
            }
        }),
        vscode.commands.registerCommand('sentra.clearDiagnostics', () => scanner.clear()),
        vscode.commands.registerCommand('sentra.showLog', () => log.show()),
        vscode.workspace.onDidOpenTextDocument(autoScan),
        vscode.workspace.onDidSaveTextDocument(autoScan),
        vscode.workspace.onDidCloseTextDocument((doc) => {
            // Keep workspace-scan results for files on disk; drop results for closed untitled buffers.
            if (doc.uri.scheme === 'untitled') {
                scanner.forget(doc.uri);
            }
        }),
        vscode.workspace.onDidChangeConfiguration((e) => {
            if (!e.affectsConfiguration(CONFIG_SECTION)) {
                return;
            }
            const cfg = getConfig();
            statusBar.setVisible(cfg.showStatusBar);
            scanner.refreshFromSettings();
            if (e.affectsConfiguration(`${CONFIG_SECTION}.enabled`) && cfg.enabled) {
                vscode.workspace.textDocuments.forEach(autoScan);
            }
        }),
    );

    // Scan documents that were already open before activation.
    vscode.workspace.textDocuments.forEach(autoScan);
}

export function deactivate(): void {}
