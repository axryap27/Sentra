import * as fs from 'fs';
import * as os from 'os';
import * as vscode from 'vscode';
import { AnalyzerError } from './analyzerBinary';
import { getConfig, SentraConfig } from './config';
import { GlobSet } from './glob';
import { AnalyzerLanguage, resolveLanguage, SUPPORTED_GLOB } from './languages';
import { ResultCache } from './resultCache';
import { SentraStatusBar } from './statusBar';
import { FileReport, Finding, SEVERITY_RANK, Severity } from './types';

export interface Analyzer {
    analyze(source: string, language: AnalyzerLanguage): Promise<Finding[]>;
}

export interface WorkspaceScanResult {
    reports: FileReport[];
    filesScanned: number;
    cacheHits: number;
    durationMs: number;
}

/**
 * Owns diagnostics and decides what to scan. Every entry point (open, save, command,
 * workspace scan) goes through the same settings checks, so `enabled`, `autoScan`,
 * `excludePatterns`, `maxFileSize`, `severityLevel` and `enableIncrementalScanning`
 * behave identically everywhere.
 */
export class Scanner implements vscode.Disposable {
    readonly diagnostics = vscode.languages.createDiagnosticCollection('sentra');
    /** Unfiltered findings per URI, so a severity change re-filters without rescanning. */
    private readonly findings = new Map<string, Finding[]>();
    private lastReport: FileReport[] | undefined;
    /** Per-URI scan counter used to discard results of superseded scans (scan-on-type). */
    private readonly generations = new Map<string, number>();

    constructor(
        private readonly analyzer: Analyzer,
        private readonly cache: ResultCache,
        private readonly statusBar: SentraStatusBar,
        private readonly log: vscode.OutputChannel,
    ) {}

    /** Returns why a URI should not be scanned, or undefined if it should. */
    skipReason(uri: vscode.Uri, cfg: SentraConfig, languageId?: string): string | undefined {
        if (!cfg.enabled) {
            return 'disabled';
        }
        if (uri.scheme !== 'file' && uri.scheme !== 'untitled') {
            return `unsupported scheme ${uri.scheme}`;
        }
        if (!resolveLanguage(languageId, uri.fsPath)) {
            return 'unsupported language';
        }
        if (uri.scheme === 'file' && isExcluded(uri, cfg.excludePatterns)) {
            return 'excluded';
        }
        return undefined;
    }

    /** Scan an open document (its in-memory text, which may be unsaved). */
    async scanDocument(doc: vscode.TextDocument): Promise<void> {
        const cfg = getConfig(doc.uri);
        const reason = this.skipReason(doc.uri, cfg, doc.languageId);
        if (reason) {
            return;
        }
        const text = doc.getText();
        if (Buffer.byteLength(text, 'utf8') > cfg.maxFileSize) {
            this.log.appendLine(`Skipping ${doc.uri.fsPath}: larger than sentra.maxFileSize`);
            return;
        }
        const language = resolveLanguage(doc.languageId, doc.uri.fsPath)!;
        const uriKey = doc.uri.toString();
        const generation = (this.generations.get(uriKey) ?? 0) + 1;
        this.generations.set(uriKey, generation);
        const version = doc.version;
        this.statusBar.setScanning();
        try {
            const { findings } = await this.analyzeCached(text, language, cfg);
            // Drop stale results: a newer scan of this document started, or it was edited meanwhile.
            if (this.generations.get(uriKey) !== generation || doc.version !== version) {
                return;
            }
            this.setFindings(doc.uri, findings);
        } catch (e) {
            this.reportError(e);
            return;
        }
        this.refreshStatus();
    }

    async scanUri(uri: vscode.Uri): Promise<void> {
        const open = vscode.workspace.textDocuments.find(
            (d) => d.uri.toString() === uri.toString(),
        );
        await this.scanDocument(open ?? (await vscode.workspace.openTextDocument(uri)));
    }

    async scanWorkspace(
        token?: vscode.CancellationToken,
        onProgress?: (done: number, total: number) => void,
    ): Promise<WorkspaceScanResult> {
        const started = Date.now();
        const cfg = getConfig();
        const exclude = cfg.excludePatterns.length
            ? `{${cfg.excludePatterns.join(',')}}`
            : undefined;
        const uris = (
            await vscode.workspace.findFiles(SUPPORTED_GLOB, exclude, undefined, token)
        ).filter((u) => !this.skipReason(u, cfg));

        const reports: FileReport[] = [];
        let done = 0;
        let cacheHits = 0;
        let firstError: unknown;
        const openDocs = new Map(vscode.workspace.textDocuments.map((d) => [d.uri.toString(), d]));

        this.statusBar.setScanning();
        const scanOne = async (uri: vscode.Uri) => {
            try {
                const doc = openDocs.get(uri.toString());
                const language = resolveLanguage(doc?.languageId, uri.fsPath)!;
                let findings: Finding[];
                if (doc?.isDirty) {
                    const r = await this.analyzeCached(doc.getText(), language, cfg);
                    findings = r.findings;
                    cacheHits += r.cached ? 1 : 0;
                } else {
                    // Read from disk directly: openTextDocument fires onDidOpen events and is much slower.
                    const stat = await fs.promises.stat(uri.fsPath);
                    if (stat.size > cfg.maxFileSize) {
                        return;
                    }
                    const known = cfg.enableIncrementalScanning
                        ? this.cache.getByStat(uri.fsPath, stat.mtimeMs, stat.size)
                        : undefined;
                    if (known) {
                        findings = known; // unchanged on disk: no read, no hash, no analysis
                        cacheHits++;
                    } else {
                        const text = await fs.promises.readFile(uri.fsPath, 'utf8');
                        const r = await this.analyzeCached(text, language, cfg);
                        findings = r.findings;
                        cacheHits += r.cached ? 1 : 0;
                        if (cfg.enableIncrementalScanning) {
                            this.cache.setStat(
                                uri.fsPath,
                                stat.mtimeMs,
                                stat.size,
                                this.cache.key(language, text),
                            );
                        }
                    }
                }
                this.setFindings(uri, findings);
                const visible = filterBySeverity(findings, cfg.severityLevel);
                if (visible.length) {
                    reports.push({
                        fileName: vscode.workspace.asRelativePath(uri),
                        uri: uri.toString(),
                        findings: visible,
                    });
                }
            } catch (e) {
                firstError ??= e;
                this.log.appendLine(`Failed to scan ${uri.fsPath}: ${String(e)}`);
            } finally {
                onProgress?.(++done, uris.length);
            }
        };

        await runPool(uris, Math.max(1, os.cpus().length), scanOne, token);
        await this.cache.flush();
        reports.sort((a, b) => a.fileName.localeCompare(b.fileName));
        this.lastReport = reports;
        if (firstError instanceof AnalyzerError && firstError.kind === 'missing-binary') {
            this.reportError(firstError);
        } else {
            this.refreshStatus();
        }
        return { reports, filesScanned: done, cacheHits, durationMs: Date.now() - started };
    }

    private async analyzeCached(
        text: string,
        language: AnalyzerLanguage,
        cfg: SentraConfig,
    ): Promise<{ findings: Finding[]; cached: boolean }> {
        if (!cfg.enableIncrementalScanning) {
            return { findings: await this.analyzer.analyze(text, language), cached: false };
        }
        const key = this.cache.key(language, text);
        const hit = this.cache.get(key);
        if (hit) {
            return { findings: hit, cached: true };
        }
        const findings = await this.analyzer.analyze(text, language);
        this.cache.set(key, findings);
        return { findings, cached: false };
    }

    private setFindings(uri: vscode.Uri, findings: Finding[]): void {
        this.findings.set(uri.toString(), findings);
        this.publish(uri, findings, getConfig(uri).severityLevel);
    }

    private publish(uri: vscode.Uri, findings: Finding[], minSeverity: Severity): void {
        this.diagnostics.set(uri, filterBySeverity(findings, minSeverity).map(toDiagnostic));
    }

    /** Re-apply settings (severity filter, enable/exclude) to existing results without rescanning. */
    refreshFromSettings(): void {
        const cfg = getConfig();
        if (!cfg.enabled) {
            this.clear();
            this.statusBar.setDisabled();
            return;
        }
        for (const [key, findings] of this.findings) {
            const uri = vscode.Uri.parse(key);
            if (this.skipReason(uri, cfg)) {
                this.findings.delete(key);
                this.diagnostics.delete(uri);
            } else {
                this.publish(uri, findings, getConfig(uri).severityLevel);
            }
        }
        this.refreshStatus();
    }

    forget(uri: vscode.Uri): void {
        this.findings.delete(uri.toString());
        this.generations.delete(uri.toString());
        this.diagnostics.delete(uri);
        this.refreshStatus();
    }

    clear(): void {
        this.findings.clear();
        this.diagnostics.clear();
        this.lastReport = undefined;
        this.refreshStatus();
    }

    /** Visible (severity-filtered) findings for a URI, for hovers. */
    getFindings(uri: vscode.Uri): Finding[] {
        return filterBySeverity(
            this.findings.get(uri.toString()) ?? [],
            getConfig(uri).severityLevel,
        );
    }

    /** All visible findings, keyed by URI string, for SARIF export. */
    allFindings(): Map<string, Finding[]> {
        const out = new Map<string, Finding[]>();
        for (const [key, findings] of this.findings) {
            const visible = filterBySeverity(
                findings,
                getConfig(vscode.Uri.parse(key)).severityLevel,
            );
            if (visible.length) {
                out.set(key, visible);
            }
        }
        return out;
    }

    getLastReport(): FileReport[] | undefined {
        return this.lastReport;
    }

    private refreshStatus(): void {
        if (!getConfig().enabled) {
            this.statusBar.setDisabled();
            return;
        }
        let count = 0;
        this.diagnostics.forEach((_uri, diags) => (count += diags.length));
        this.statusBar.setIssues(count);
    }

    private reportError(e: unknown): void {
        const message = e instanceof Error ? e.message : String(e);
        this.log.appendLine(`Analyzer error: ${message}`);
        this.statusBar.setError(message);
    }

    async dispose(): Promise<void> {
        this.diagnostics.dispose();
        await this.cache.flush();
    }
}

export function filterBySeverity(findings: Finding[], min: Severity): Finding[] {
    const floor = SEVERITY_RANK[min];
    return findings.filter((f) => SEVERITY_RANK[f.severity] >= floor);
}

function toDiagnostic(f: Finding): vscode.Diagnostic {
    const line = Math.max(0, f.line - 1);
    const col = Math.max(0, (f.column ?? 1) - 1);
    // Underline the node itself when it is on one line, otherwise the rest of the first line.
    const endCol =
        f.endLine === f.line && f.endColumn && f.endColumn > (f.column ?? 1)
            ? f.endColumn - 1
            : Number.MAX_SAFE_INTEGER;
    const range = new vscode.Range(line, col, line, endCol);
    const severity =
        f.severity === 'High'
            ? vscode.DiagnosticSeverity.Error
            : f.severity === 'Medium'
              ? vscode.DiagnosticSeverity.Warning
              : vscode.DiagnosticSeverity.Information;
    const d = new vscode.Diagnostic(range, f.issue, severity);
    d.source = 'Sentra';
    if (f.rule) {
        // The rule ID is the code (quick fixes read it); it links to the CWE entry.
        d.code = f.cwe ? { value: f.rule, target: cweUri(f.cwe) } : f.rule;
    }
    return d;
}

function cweUri(cwe: string): vscode.Uri {
    return vscode.Uri.parse(
        `https://cwe.mitre.org/data/definitions/${cwe.replace(/^CWE-/, '')}.html`,
    );
}

function isExcluded(uri: vscode.Uri, patterns: string[]): boolean {
    if (!patterns.length) {
        return false;
    }
    const set = new GlobSet(patterns);
    const rel = vscode.workspace.asRelativePath(uri, false).replace(/\\/g, '/');
    return set.matches(rel) || set.matches(uri.fsPath.replace(/\\/g, '/'));
}

/** Run `fn` over items with bounded concurrency. */
async function runPool<T>(
    items: T[],
    limit: number,
    fn: (item: T) => Promise<void>,
    token?: vscode.CancellationToken,
): Promise<void> {
    let next = 0;
    const worker = async () => {
        while (next < items.length && !token?.isCancellationRequested) {
            await fn(items[next++]);
        }
    };
    await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
}
