/**
 * Minimal glob matcher for `sentra.excludePatterns` so the same patterns apply to
 * single-file scans (on open/save) and workspace scans. Supports **, *, ? and {a,b}.
 */
export function globToRegExp(glob: string): RegExp {
    let re = '';
    let i = 0;
    let inGroup = false;
    while (i < glob.length) {
        const c = glob[i];
        if (c === '*') {
            if (glob[i + 1] === '*') {
                const atSegmentStart = i === 0 || glob[i - 1] === '/';
                if (glob[i + 2] === '/' && atSegmentStart) {
                    re += '(?:.*/)?'; // "**/" matches zero or more directories
                    i += 3;
                    continue;
                }
                re += '.*';
                i += 2;
                continue;
            }
            re += '[^/]*';
        } else if (c === '?') {
            re += '[^/]';
        } else if (c === '{') {
            inGroup = true;
            re += '(?:';
        } else if (c === '}' && inGroup) {
            inGroup = false;
            re += ')';
        } else if (c === ',' && inGroup) {
            re += '|';
        } else {
            re += c.replace(/[.+^$()|[\]\\]/g, '\\$&');
        }
        i++;
    }
    return new RegExp(`^${re}$`);
}

export class GlobSet {
    private readonly regexes: RegExp[];

    constructor(patterns: string[]) {
        this.regexes = patterns.map(globToRegExp);
    }

    /** Matches a path given with forward slashes (workspace-relative or absolute). */
    matches(posixPath: string): boolean {
        return this.regexes.some((r) => r.test(posixPath));
    }
}
