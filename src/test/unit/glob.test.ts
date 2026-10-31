import * as assert from 'assert';
import { GlobSet } from '../../glob';

describe('GlobSet', () => {
    const set = new GlobSet(['**/test/**', '**/*.min.js', '{a,b}/x.py', 'src/?.ts']);

    it('matches ** at the start and middle', () => {
        assert.ok(set.matches('test/a.py'));
        assert.ok(set.matches('src/test/deep/b.py'));
        assert.ok(!set.matches('src/tests/c.py'));
    });

    it('matches extensions and brace groups', () => {
        assert.ok(set.matches('x.min.js'));
        assert.ok(set.matches('dir/y.min.js'));
        assert.ok(set.matches('a/x.py'));
        assert.ok(!set.matches('c/x.py'));
    });

    it('treats ? as one non-separator character', () => {
        assert.ok(set.matches('src/a.ts'));
        assert.ok(!set.matches('src/ab.ts'));
    });

    it('escapes regex metacharacters', () => {
        assert.ok(new GlobSet(['a+b(1).py']).matches('a+b(1).py'));
        assert.ok(!new GlobSet(['a+b(1).py']).matches('aab1.py'));
    });
});
