import * as assert from 'assert';
import * as vscode from 'vscode';

const folder = () => vscode.workspace.workspaceFolders![0].uri;
const file = (rel: string) => vscode.Uri.joinPath(folder(), rel);

async function waitFor<T>(fn: () => T | undefined, what: string, ms = 15_000): Promise<T> {
    const end = Date.now() + ms;
    for (;;) {
        const v = fn();
        if (v !== undefined) {
            return v;
        }
        if (Date.now() > end) {
            throw new Error(`timed out waiting for ${what}`);
        }
        await new Promise((r) => setTimeout(r, 100));
    }
}

const sentraDiagnostics = (uri: vscode.Uri) =>
    vscode.languages.getDiagnostics(uri).filter((d) => d.source === 'Sentra');
const ruleOf = (d: vscode.Diagnostic) => String(typeof d.code === 'object' ? d.code.value : d.code);
const settle = () => new Promise((r) => setTimeout(r, 1500));

async function setting(key: string, value: unknown): Promise<void> {
    await vscode.workspace
        .getConfiguration('sentra')
        .update(key, value, vscode.ConfigurationTarget.Workspace);
}

describe('Sentra extension', () => {
    const py = () => file('src/vulnerable_python.py');

    before(async () => {
        await vscode.extensions.getExtension('aaryapatel.sentra')!.activate();
    });

    afterEach(async () => {
        for (const k of ['enabled', 'autoScan', 'severityLevel', 'excludePatterns', 'scanOnType']) {
            await setting(k, undefined);
        }
    });

    it('scans a file on open and reports rule IDs with CWE links', async () => {
        await vscode.window.showTextDocument(py());
        const diags = await waitFor(
            () => (sentraDiagnostics(py()).length >= 5 ? sentraDiagnostics(py()) : undefined),
            'diagnostics',
        );
        const rules = new Set(diags.map(ruleOf));
        for (const r of [
            'code_injection',
            'command_injection',
            'unsafe_deserialization',
            'weak_crypto',
        ]) {
            assert.ok(rules.has(r), `missing ${r} in ${[...rules]}`);
        }
        const withLink = diags.find((d) => typeof d.code === 'object');
        assert.match(String((withLink!.code as { target: vscode.Uri }).target), /cwe\.mitre\.org/);
    });

    it('severityLevel filters existing results without a rescan', async () => {
        await vscode.window.showTextDocument(py());
        await waitFor(
            () =>
                sentraDiagnostics(py()).some((d) => ruleOf(d) === 'weak_crypto') ? true : undefined,
            'weak_crypto',
        );
        await setting('severityLevel', 'High');
        await waitFor(
            () =>
                sentraDiagnostics(py()).some((d) => ruleOf(d) === 'weak_crypto') ? undefined : true,
            'Medium findings hidden',
        );
        assert.ok(sentraDiagnostics(py()).length > 0, 'High findings remain');
    });

    it('enabled=false clears diagnostics and re-enabling rescans', async () => {
        await vscode.window.showTextDocument(py());
        await waitFor(() => (sentraDiagnostics(py()).length ? true : undefined), 'diagnostics');
        await setting('enabled', false);
        await waitFor(() => (sentraDiagnostics(py()).length === 0 ? true : undefined), 'cleared');
        await setting('enabled', true);
        await waitFor(() => (sentraDiagnostics(py()).length ? true : undefined), 'rescanned');
    });

    it('autoScan=false: opening a file does not scan it', async () => {
        await setting('autoScan', false);
        const uri = file('src/vulnerable_js.js');
        await vscode.window.showTextDocument(uri);
        await settle();
        assert.strictEqual(sentraDiagnostics(uri).length, 0);
        await vscode.commands.executeCommand('sentra.scanFile', uri);
        await waitFor(
            () => (sentraDiagnostics(uri).length ? true : undefined),
            'manual scan still works',
        );
    });

    it('excludePatterns applies to single-file scans', async () => {
        const uri = file('vendor/skip.py');
        await setting('excludePatterns', ['**/vendor/**']);
        await vscode.window.showTextDocument(uri);
        await settle();
        assert.strictEqual(sentraDiagnostics(uri).length, 0);
        await setting('excludePatterns', []);
        await vscode.commands.executeCommand('sentra.scanFile', uri);
        await waitFor(
            () => (sentraDiagnostics(uri).length ? true : undefined),
            'scanned once not excluded',
        );
    });

    it('scans as you type (debounced)', async () => {
        const doc = await vscode.workspace.openTextDocument({
            language: 'python',
            content: 'x = 1\n',
        });
        const editor = await vscode.window.showTextDocument(doc);
        await settle();
        assert.strictEqual(sentraDiagnostics(doc.uri).length, 0);
        await editor.edit((e) =>
            e.insert(new vscode.Position(1, 0), 'import os\nos.system("rm " + input())\n'),
        );
        const d = await waitFor(() => sentraDiagnostics(doc.uri)[0], 'scan-on-type');
        assert.strictEqual(ruleOf(d), 'command_injection');
    });

    it('offers quick fixes and hovers', async () => {
        const editor = await vscode.window.showTextDocument(py());
        const md5 = await waitFor(
            () => sentraDiagnostics(py()).find((d) => ruleOf(d) === 'weak_crypto'),
            'weak_crypto',
        );
        const actions = await vscode.commands.executeCommand<vscode.CodeAction[]>(
            'vscode.executeCodeActionProvider',
            py(),
            md5.range,
        );
        const titles = actions.map((a) => a.title);
        assert.ok(
            titles.some((t) => t.includes('sha256')),
            `no sha256 fix in ${titles}`,
        );
        assert.ok(
            titles.some((t) => t.includes('sentra-ignore')),
            'no suppression fix',
        );

        const hovers = await vscode.commands.executeCommand<vscode.Hover[]>(
            'vscode.executeHoverProvider',
            py(),
            md5.range.start,
        );
        const text = hovers
            .flatMap((h) =>
                h.contents.map((c) =>
                    typeof c === 'string' ? c : (c as vscode.MarkdownString).value,
                ),
            )
            .join('\n');
        assert.match(text, /CWE-327/);
        assert.ok(editor);
    });

    it('scanWorkspace reports unopened files and skips excluded ones', async () => {
        await setting('excludePatterns', ['**/vendor/**']);
        await vscode.commands.executeCommand('sentra.scanWorkspace');
        const c = file('src/vulnerable.c');
        await waitFor(() => (sentraDiagnostics(c).length ? true : undefined), 'C diagnostics');
        assert.strictEqual(sentraDiagnostics(file('vendor/skip.py')).length, 0);
    });
});
