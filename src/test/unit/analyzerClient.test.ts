import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import { DaemonClient, parseFindings } from '../../analyzerClient';
import { AnalyzerError, findAnalyzerBinary } from '../../analyzerBinary';

const root = path.resolve(__dirname, '..', '..', '..');
const binary = findAnalyzerBinary(root);

describe('parseFindings', () => {
    it('keeps well-formed findings and drops junk', () => {
        const out = parseFindings([
            { line: 1, issue: 'x', severity: 'High' },
            { line: 'no' },
            null,
            { line: 2, issue: 'y', severity: 'Bogus' },
        ]);
        assert.strictEqual(out.length, 1);
    });

    it('rejects non-arrays with a typed error', () => {
        assert.throws(
            () => parseFindings({}),
            (e: unknown) => e instanceof AnalyzerError && e.kind === 'bad-output',
        );
    });
});

describe('DaemonClient (real analyzer)', function () {
    this.timeout(20_000);
    before(function () {
        if (!binary) {
            this.skip(); // run `make go-build` first
        }
    });

    it('analyzes pipelined requests over one process', async () => {
        const client = new DaemonClient(binary!);
        try {
            const src = "import os\nos.system('rm ' + input())\n";
            const results = await Promise.all(
                Array.from({ length: 20 }, () => client.analyze(src, 'python')),
            );
            for (const r of results) {
                assert.strictEqual(r.length, 1);
                assert.strictEqual(r[0].rule, 'command_injection');
                assert.strictEqual(r[0].line, 2);
            }
        } finally {
            client.dispose();
        }
    });

    it('never passes source through a shell', async () => {
        const client = new DaemonClient(binary!);
        const marker = path.join(root, 'out', 'pwned');
        try {
            await client.analyze(`$(touch ${marker}); \`touch ${marker}\``, 'python');
            assert.ok(!fs.existsSync(marker));
        } finally {
            client.dispose();
        }
    });

    it('reports analyzer errors per request without killing the daemon', async () => {
        const client = new DaemonClient(binary!);
        try {
            await assert.rejects(client.analyze('x', 'klingon' as never), /unsupported language/);
            const ok = await client.analyze('eval(input())\n', 'python');
            assert.strictEqual(ok[0]?.rule, 'code_injection');
        } finally {
            client.dispose();
        }
    });

    it('fails fast with a typed error when the binary is missing', async () => {
        const client = new DaemonClient(path.join(root, 'does-not-exist'));
        await assert.rejects(
            client.analyze('x', 'python'),
            (e: unknown) => e instanceof AnalyzerError && e.kind === 'crash',
        );
        client.dispose();
    });
});
