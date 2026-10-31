import { ChildProcessWithoutNullStreams, spawn } from 'child_process';
import { AnalyzerError } from './analyzerBinary';
import { AnalyzerLanguage } from './languages';
import { Finding, isSeverity } from './types';

const REQUEST_TIMEOUT_MS = 30_000;
const MAX_RESTARTS = 3;
const RESTART_WINDOW_MS = 60_000;

interface Pending {
    resolve: (f: Finding[]) => void;
    reject: (e: Error) => void;
    timer: NodeJS.Timeout;
}

/**
 * Client for the long-lived analyzer daemon (`sentra-analyzer --serve`). The model
 * and grammars are loaded once; requests are newline-delimited JSON over stdio,
 * pipelined and matched by id, and the daemon analyzes them in parallel.
 *
 * The binary is spawned directly with an argv array (never through a shell), and
 * source travels over stdin, so no temp files are written. If the daemon dies it is
 * restarted on the next request, up to MAX_RESTARTS times per RESTART_WINDOW_MS.
 */
export class DaemonClient {
    private proc: ChildProcessWithoutNullStreams | undefined;
    private readonly pending = new Map<number, Pending>();
    private nextId = 1;
    private buffer = '';
    private restarts: number[] = [];
    private disposed = false;

    constructor(
        private readonly binaryPath: string,
        private readonly log: (msg: string) => void = () => undefined,
    ) {}

    analyze(source: string, language: AnalyzerLanguage): Promise<Finding[]> {
        return this.request('analyze', { language, content: source });
    }

    private request(method: string, params: object): Promise<Finding[]> {
        if (this.disposed) {
            return Promise.reject(new AnalyzerError('crash', 'Analyzer client was disposed'));
        }
        let proc: ChildProcessWithoutNullStreams;
        try {
            proc = this.ensureProcess();
        } catch (e) {
            return Promise.reject(e);
        }
        const id = this.nextId++;
        return new Promise<Finding[]>((resolve, reject) => {
            const timer = setTimeout(() => {
                this.pending.delete(id);
                reject(
                    new AnalyzerError(
                        'timeout',
                        `Analyzer timed out after ${REQUEST_TIMEOUT_MS} ms`,
                    ),
                );
                // A wedged worker would otherwise hold a slot forever: restart the daemon.
                this.log('Analyzer request timed out; restarting daemon');
                this.proc?.kill();
            }, REQUEST_TIMEOUT_MS);
            this.pending.set(id, { resolve, reject, timer });
            proc.stdin.write(JSON.stringify({ id, method, params }) + '\n');
        });
    }

    private ensureProcess(): ChildProcessWithoutNullStreams {
        if (this.proc) {
            return this.proc;
        }
        const now = Date.now();
        this.restarts = this.restarts.filter((t) => now - t < RESTART_WINDOW_MS);
        if (this.restarts.length > MAX_RESTARTS) {
            throw new AnalyzerError(
                'crash',
                `Analyzer crashed ${this.restarts.length} times in the last minute; giving up`,
            );
        }
        this.restarts.push(now);

        const proc = spawn(this.binaryPath, ['--serve'], {
            stdio: ['pipe', 'pipe', 'pipe'],
            windowsHide: true,
            // cgocheck validates Go->C pointer passing on every tree-sitter call (~9% of CPU);
            // it is a debugging aid and safe to disable for the shipped binary.
            env: { ...process.env, GODEBUG: 'cgocheck=0' },
        });
        proc.stdout.setEncoding('utf8');
        proc.stdout.on('data', (chunk: string) => this.onData(chunk));
        proc.stderr.on('data', (d: Buffer) => this.log(`[analyzer] ${d.toString().trimEnd()}`));
        proc.stdin.on('error', () => undefined); // EPIPE when the daemon dies; handled by 'exit'
        proc.on('error', (e) => this.onExit(proc, `failed to start: ${e.message}`));
        proc.on('exit', (code, signal) =>
            this.onExit(proc, `exited (code ${code}, signal ${signal})`),
        );
        this.proc = proc;
        this.buffer = '';
        this.log(`Started analyzer daemon (pid ${proc.pid})`);
        return proc;
    }

    private onData(chunk: string): void {
        this.buffer += chunk;
        let nl: number;
        while ((nl = this.buffer.indexOf('\n')) >= 0) {
            const line = this.buffer.slice(0, nl);
            this.buffer = this.buffer.slice(nl + 1);
            if (line.trim()) {
                this.onLine(line);
            }
        }
    }

    private onLine(line: string): void {
        let msg: { id?: unknown; result?: { findings?: unknown }; error?: unknown };
        try {
            msg = JSON.parse(line);
        } catch {
            this.log(`Malformed response from analyzer: ${line.slice(0, 200)}`);
            return;
        }
        const p = typeof msg.id === 'number' ? this.pending.get(msg.id) : undefined;
        if (!p) {
            if (msg.error) {
                this.log(`Analyzer error: ${String(msg.error)}`);
            }
            return;
        }
        this.pending.delete(msg.id as number);
        clearTimeout(p.timer);
        if (msg.error) {
            p.reject(new AnalyzerError('crash', String(msg.error)));
            return;
        }
        try {
            p.resolve(parseFindings(msg.result?.findings));
        } catch (e) {
            p.reject(e as Error);
        }
    }

    private onExit(proc: ChildProcessWithoutNullStreams, why: string): void {
        if (this.proc !== proc) {
            return; // already handled (error + exit both fire)
        }
        this.proc = undefined;
        if (!this.disposed) {
            this.log(`Analyzer daemon ${why}`);
        }
        const err = new AnalyzerError('crash', `Analyzer ${why}`);
        for (const p of this.pending.values()) {
            clearTimeout(p.timer);
            p.reject(err);
        }
        this.pending.clear();
    }

    dispose(): void {
        this.disposed = true;
        const proc = this.proc;
        if (!proc) {
            return;
        }
        proc.stdin.end(JSON.stringify({ id: 0, method: 'shutdown' }) + '\n');
        setTimeout(() => proc.kill(), 1000).unref();
    }
}

/** Validate analyzer output instead of trusting it blindly. */
export function parseFindings(data: unknown): Finding[] {
    if (!Array.isArray(data)) {
        throw new AnalyzerError('bad-output', 'Analyzer response has no findings array');
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
