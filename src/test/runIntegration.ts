import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runTests } from '@vscode/test-electron';

/** Launch VS Code with the extension and a scratch workspace, then run out/test/integration. */
async function main(): Promise<void> {
    const root = path.resolve(__dirname, '..', '..');
    const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-it-'));
    fs.cpSync(path.join(root, 'test_files'), path.join(workspace, 'src'), { recursive: true });
    fs.mkdirSync(path.join(workspace, 'vendor'));
    fs.writeFileSync(
        path.join(workspace, 'vendor', 'skip.py'),
        "import os\nos.system('rm ' + input())\n",
    );
    try {
        await runTests({
            extensionDevelopmentPath: root,
            extensionTestsPath: path.join(__dirname, 'integration', 'index'),
            launchArgs: [
                workspace,
                '--disable-extensions',
                '--skip-welcome',
                '--skip-release-notes',
            ],
        });
    } finally {
        fs.rmSync(workspace, { recursive: true, force: true });
    }
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
