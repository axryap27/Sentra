// End-to-end latency from Node, the way the extension talks to the analyzer.
//
//   node scripts/bench-daemon.mjs <binary> <corpus-dir> [--sample N]
//
// Compares (a) spawning the analyzer once per file (the pre-0.3 design) with
// (b) one long-lived `--serve` daemon, sequential round trips, and (c) the daemon
// with all files pipelined (workspace scan). Prints JSON.
import { spawn } from 'node:child_process';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { cpus } from 'node:os';
import { extname, join } from 'node:path';

const [bin, root, ...rest] = process.argv.slice(2);
const sample = Number(rest[rest.indexOf('--sample') + 1]) || 300;
const LANG = { '.py': 'python', '.js': 'javascript', '.ts': 'typescript', '.java': 'java', '.c': 'c', '.cpp': 'cpp', '.go': 'go', '.php': 'php', '.cs': 'csharp', '.rs': 'rust' };
const env = { ...process.env, GODEBUG: 'cgocheck=0' };

function walk(dir, out = []) {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
        const p = join(dir, e.name);
        if (e.isDirectory()) { if (e.name !== '.git' && e.name !== 'node_modules') walk(p, out); }
        else if (LANG[extname(p)] && statSync(p).size <= 1 << 20) out.push({ path: p, language: LANG[extname(p)], content: readFileSync(p, 'utf8') });
    }
    return out;
}

const pct = (xs, p) => { const s = [...xs].sort((a, b) => a - b); return +s[Math.min(s.length - 1, Math.floor(p * s.length))].toFixed(2); };
const summary = (xs) => ({ n: xs.length, p50: pct(xs, 0.5), p90: pct(xs, 0.9), p99: pct(xs, 0.99) });

function spawnOnce(f) {
    return new Promise((resolve, reject) => {
        const t0 = performance.now();
        const c = spawn(bin, ['--stdin', '--lang', f.language], { env });
        let out = '';
        c.stdout.on('data', (d) => (out += d));
        c.on('close', (code) => (code === 0 ? (JSON.parse(out), resolve(performance.now() - t0)) : reject(new Error(`exit ${code}`))));
        c.stdin.end(f.content);
    });
}

function daemon() {
    const c = spawn(bin, ['--serve'], { env });
    const pending = new Map();
    let buf = '', id = 0;
    c.stdout.setEncoding('utf8');
    c.stdout.on('data', (d) => {
        buf += d;
        let i;
        while ((i = buf.indexOf('\n')) >= 0) {
            const m = JSON.parse(buf.slice(0, i)); buf = buf.slice(i + 1);
            pending.get(m.id)?.(m); pending.delete(m.id);
        }
    });
    return {
        analyze: (f) => new Promise((resolve) => { const n = ++id; pending.set(n, resolve); c.stdin.write(JSON.stringify({ id: n, method: 'analyze', params: { language: f.language, content: f.content } }) + '\n'); }),
        close: () => c.stdin.end(JSON.stringify({ id: 0, method: 'shutdown' }) + '\n'),
    };
}

const files = walk(root);
const step = Math.max(1, Math.floor(files.length / sample));
const subset = files.filter((_, i) => i % step === 0).slice(0, sample);

const spawnLat = [];
for (const f of subset) spawnLat.push(await spawnOnce(f));

const d = daemon();
await d.analyze(subset[0]); // warm-up (process start + model load)
const daemonLat = [];
for (const f of subset) { const t0 = performance.now(); await d.analyze(f); daemonLat.push(performance.now() - t0); }

const t0 = performance.now();
let findings = 0;
await Promise.all(files.map(async (f) => { const r = await d.analyze(f); findings += r.result.findings.length; }));
const workspaceMs = performance.now() - t0;
d.close();

const lines = files.reduce((n, f) => n + f.content.split('\n').length - 1, 0);
console.log(JSON.stringify({
    corpus: root, files: files.length, lines, findings, cpus: cpus().length,
    spawn_per_file_ms: summary(spawnLat),
    daemon_round_trip_ms: summary(daemonLat),
    daemon_workspace_pipelined_ms: Math.round(workspaceMs),
    daemon_workspace_lines_per_sec: Math.round(lines / (workspaceMs / 1000)),
}, null, 2));
