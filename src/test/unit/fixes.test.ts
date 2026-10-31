import * as assert from 'assert';
import { Fix, findCall, fixesFor, suppressFix } from '../../fixes';

function apply(line: string, fix: Fix): string {
    let out = line;
    for (const e of [...fix.edits].sort((a, b) => b.start - a.start)) {
        out = out.slice(0, e.start) + e.newText + out.slice(e.end);
    }
    return out;
}

function only(rule: string, line: string, lang: string, doc = ''): string {
    const fixes = fixesFor(rule, line, lang, doc);
    assert.strictEqual(
        fixes.length,
        1,
        `expected one fix for ${line}, got ${fixes.map((f) => f.title)}`,
    );
    return apply(line, fixes[0]);
}

describe('quick fixes', () => {
    it('replaces weak hashes', () => {
        assert.strictEqual(
            only('weak_crypto', 'h = hashlib.md5(data)', 'python'),
            'h = hashlib.sha256(data)',
        );
        assert.strictEqual(
            only('weak_crypto', 'MessageDigest.getInstance("SHA-1")', 'java'),
            'MessageDigest.getInstance("SHA-256")',
        );
        assert.strictEqual(
            only('weak_crypto', "createHash('md5')", 'javascript'),
            "createHash('sha256')",
        );
    });

    it('removes shell=True', () => {
        const fixes = fixesFor(
            'command_injection',
            'subprocess.run("ls " + p, shell=True)',
            'python',
            'import os\n',
        );
        assert.strictEqual(
            apply('subprocess.run("ls " + p, shell=True)', fixes[0]),
            'subprocess.run(shlex.split("ls " + p))',
        );
        assert.strictEqual(fixes[0].addImport, 'import shlex');
        const noImport = fixesFor(
            'command_injection',
            'run(cmd, shell=True)',
            'python',
            'import shlex\n',
        );
        assert.strictEqual(noImport[0].addImport, undefined);
        assert.strictEqual(
            only('command_injection', 'run(["ls", p], shell=True)', 'python'),
            'run(["ls", p])',
        );
    });

    it('switches to yaml.safe_load and drops Loader', () => {
        assert.strictEqual(
            only('unsafe_deserialization', 'c = yaml.load(f, Loader=yaml.Loader)', 'python'),
            'c = yaml.safe_load(f)',
        );
    });

    it('replaces Math.random()', () => {
        assert.strictEqual(
            only('weak_randomness', 'x = Math.random();', 'javascript'),
            'x = (crypto.getRandomValues(new Uint32Array(1))[0] / 4294967296);',
        );
    });

    it('bounds C string functions', () => {
        assert.strictEqual(
            only('buffer_overflow', 'strcpy(buf, s);', 'c'),
            'snprintf(buf, sizeof(buf), "%s", s);',
        );
        assert.strictEqual(
            only('buffer_overflow', 'gets(buf);', 'c'),
            'fgets(buf, sizeof(buf), stdin);',
        );
        assert.deepStrictEqual(
            fixesFor('buffer_overflow', 'fgets(buf, n, f);', 'c'),
            [],
            'fgets must not match gets',
        );
    });

    it('does not offer fixes it cannot apply safely', () => {
        assert.deepStrictEqual(fixesFor('sql_injection', 'cur.execute(q)', 'python'), []);
        assert.deepStrictEqual(
            fixesFor('buffer_overflow', 'strcpy(buf,', 'c'),
            [],
            'multi-line call',
        );
    });

    it('adds suppression comments in the right syntax', () => {
        assert.strictEqual(
            apply('x = md5(a)', suppressFix('x = md5(a)', 'weak_crypto', 'python')),
            'x = md5(a) # sentra-ignore: weak_crypto',
        );
        assert.strictEqual(
            apply('x();', suppressFix('x();', 'xss', 'javascript')),
            'x(); // sentra-ignore: xss',
        );
    });

    it('findCall splits top-level arguments', () => {
        const c = findCall('f(a, g(b, c), "x,y")', 'f');
        assert.deepStrictEqual(
            c?.args.map((a) => a.text),
            ['a', 'g(b, c)', '"x,y"'],
        );
    });
});
