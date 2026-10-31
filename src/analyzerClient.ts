import { spawn } from 'child_process';
import { AnalyzerError } from './analyzerBinary';
import { AnalyzerLanguage } from './languages';
import { Finding, isSeverity } from './types';

const SCAN_TIMEOUT_MS = 30_000;

/**
 * Runs the analyzer once per scan. The binary is executed directly with an argv
 * array (no shell), and source is passed over stdin, so file paths and file
 * contents are never interpreted by a shell and no temp files are written.
 */
export class AnalyzerClient {
    constructor(private readonly binaryPath: string) {}

    analyze(source: string, language: AnalyzerLanguage): Promise<Finding[]> {
        return new Promise((resolve, reject) => {
            const child = spawn(
                this.binaryPath,
                ['--stdin', '--lang', language, '--format', 'json'],
                {
                    stdio: ['pipe', 'pipe', 'pipe'],
                    windowsHide: true,
                },
            );
            const out: Buffer[] = [];
            const err: Buffer[] = [];
            let settled = false;
            const finish = (fn: () => void) => {
                if (!settled) {
                    settled = true;
                    clearTimeout(timer);
                    fn();
                }
            };
            const timer = setTimeout(() => {
                child.kill();
                finish(() =>
                    reject(
                        new AnalyzerError(
                            'timeout',
                            `Analyzer timed out after ${SCAN_TIMEOUT_MS} ms`,
                        ),
                    ),
                );
            }, SCAN_TIMEOUT_MS);

            child.stdout.on('data', (d: Buffer) => out.push(d));
            child.stderr.on('data', (d: Buffer) => err.push(d));
            child.on('error', (e) => finish(() => reject(new AnalyzerError('crash', e.message))));
            child.on('close', (code, signal) =>
                finish(() => {
                    if (code !== 0) {
                        const detail = Buffer.concat(err).toString().trim() || `signal ${signal}`;
                        reject(
                            new AnalyzerError(
                                'crash',
                                `Analyzer exited with code ${code}: ${detail}`,
                            ),
                        );
                        return;
                    }
                    try {
                        resolve(parseFindings(Buffer.concat(out).toString()));
                    } catch (e) {
                        reject(e);
                    }
                }),
            );
            child.stdin.on('error', () => undefined); // EPIPE if the child dies early; reported via 'close'
            child.stdin.end(source, 'utf8');
        });
    }

    dispose(): void {}
}

/** Validate analyzer output instead of trusting it blindly. */
export function parseFindings(raw: string): Finding[] {
    let data: unknown;
    try {
        data = JSON.parse(raw.trim() || '[]');
    } catch {
        throw new AnalyzerError(
            'bad-output',
            `Analyzer returned malformed JSON: ${raw.slice(0, 200)}`,
        );
    }
    if (!Array.isArray(data)) {
        throw new AnalyzerError('bad-output', 'Analyzer output is not an array');
    }
    return data.filter(isFinding);
}

function isFinding(v: unknown): v is Finding {
    if (typeof v !== 'object' || v === null) {
        return false;
    }
    const f = v as Record<string, unknown>;
    return typeof f.line === 'number' && typeof f.issue === 'string' && isSeverity(f.severity);
}
