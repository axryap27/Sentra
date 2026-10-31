import * as fs from 'fs';
import * as path from 'path';
import Mocha from 'mocha';

export function run(): Promise<void> {
    const mocha = new Mocha({ ui: 'bdd', timeout: 30_000, color: true });
    for (const f of fs.readdirSync(__dirname).filter((f) => f.endsWith('.test.js'))) {
        mocha.addFile(path.join(__dirname, f));
    }
    return new Promise((resolve, reject) =>
        mocha.run((failures) =>
            failures ? reject(new Error(`${failures} integration test(s) failed`)) : resolve(),
        ),
    );
}
