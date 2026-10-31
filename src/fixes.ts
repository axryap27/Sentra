/**
 * Quick-fix text transforms. Pure functions over one line of source so they can be
 * unit-tested without VS Code; quickFixes.ts turns them into CodeActions.
 */

export interface LineEdit {
    start: number; // column, inclusive
    end: number; // column, exclusive
    newText: string;
}

export interface Fix {
    title: string;
    edits: LineEdit[];
    /** An import line to add at the top of the file if it is not there yet. */
    addImport?: string;
    preferred?: boolean;
}

interface Call {
    nameStart: number;
    open: number; // index of '('
    close: number; // index of matching ')'
    args: { text: string; start: number; end: number }[];
}

/** Locate `name(` on the line (name may be dotted) and split its top-level arguments. */
export function findCall(line: string, name: string, from = 0): Call | undefined {
    const re = new RegExp(`(^|[^\\w.$])(${name.replace(/[.$]/g, '\\$&')})\\s*\\(`, 'g');
    re.lastIndex = from;
    const m = re.exec(line);
    if (!m) {
        return undefined;
    }
    const nameStart = m.index + m[1].length;
    const open = m.index + m[0].length - 1;
    const args: Call['args'] = [];
    let depth = 0;
    let quote = '';
    let argStart = open + 1;
    for (let i = open + 1; i < line.length; i++) {
        const c = line[i];
        if (quote) {
            if (c === '\\') {
                i++;
            } else if (c === quote) {
                quote = '';
            }
            continue;
        }
        if (c === '"' || c === "'" || c === '`') {
            quote = c;
        } else if (c === '(' || c === '[' || c === '{') {
            depth++;
        } else if (c === ')' || c === ']' || c === '}') {
            if (depth === 0) {
                if (line.slice(argStart, i).trim()) {
                    args.push(trimmedArg(line, argStart, i));
                }
                return { nameStart, open, close: i, args };
            }
            depth--;
        } else if (c === ',' && depth === 0) {
            args.push(trimmedArg(line, argStart, i));
            argStart = i + 1;
        }
    }
    return undefined; // call spans lines: not handled
}

function trimmedArg(line: string, start: number, end: number) {
    const raw = line.slice(start, end);
    const lead = raw.length - raw.trimStart().length;
    const text = raw.trim();
    return { text, start: start + lead, end: start + lead + text.length };
}

const COMMENT: Record<string, string> = {
    python: '#',
    php: '//',
};

/** Fix that appends a suppression comment for this rule. */
export function suppressFix(line: string, rule: string, languageId: string): Fix {
    const token = COMMENT[languageId] ?? '//';
    return {
        title: `Suppress "${rule}" on this line (${token} sentra-ignore)`,
        edits: [
            { start: line.length, end: line.length, newText: ` ${token} sentra-ignore: ${rule}` },
        ],
    };
}

/** Rule-specific fixes for a finding on `line`. */
export function fixesFor(rule: string, line: string, languageId: string, documentText = ''): Fix[] {
    switch (rule) {
        case 'weak_crypto':
            return weakCryptoFixes(line, languageId);
        case 'command_injection':
            return shellTrueFixes(line, documentText);
        case 'unsafe_deserialization':
            return yamlFixes(line);
        case 'weak_randomness':
            return mathRandomFixes(line);
        case 'buffer_overflow':
            return cStringFixes(line);
        default:
            return [];
    }
}

function weakCryptoFixes(line: string, languageId: string): Fix[] {
    const fixes: Fix[] = [];
    if (languageId === 'python') {
        const m = /hashlib\.(md5|sha1)\s*\(/.exec(line);
        if (m) {
            const start = m.index + 'hashlib.'.length;
            fixes.push({
                title: `Use hashlib.sha256 instead of ${m[1]}`,
                preferred: true,
                edits: [{ start, end: start + m[1].length, newText: 'sha256' }],
            });
        }
    }
    // String literal algorithm names: hashlib.new('md5'), MessageDigest.getInstance("SHA-1"), createHash('md5')
    const lit = /(["'])(md5|MD5|sha1|SHA1|SHA-1|sha-1)\1/.exec(line);
    if (lit && /getInstance|createHash|hashlib\.new|new\s*\(/.test(line)) {
        const javaStyle = /getInstance/.test(line);
        const replacement = javaStyle ? 'SHA-256' : 'sha256';
        fixes.push({
            title: `Use ${replacement} instead of ${lit[2]}`,
            preferred: true,
            edits: [
                { start: lit.index + 1, end: lit.index + 1 + lit[2].length, newText: replacement },
            ],
        });
    }
    return fixes;
}

function shellTrueFixes(line: string, documentText: string): Fix[] {
    const kw = /,\s*shell\s*=\s*True/.exec(line);
    if (!kw) {
        return [];
    }
    // Find the call that contains the keyword: the last unclosed '(' before it.
    let depth = 0;
    let open = -1;
    for (let i = kw.index - 1; i >= 0; i--) {
        if (line[i] === ')') {
            depth++;
        } else if (line[i] === '(') {
            if (depth === 0) {
                open = i;
                break;
            }
            depth--;
        }
    }
    if (open < 0) {
        return [];
    }
    const nameMatch = /[\w.]+\s*$/.exec(line.slice(0, open));
    const call = nameMatch
        ? findCall(line, nameMatch[0].trim(), nameMatch.index > 0 ? nameMatch.index - 1 : 0)
        : undefined;
    const first = call?.args[0];
    if (!first) {
        return [];
    }
    const removeKw: LineEdit = { start: kw.index, end: kw.index + kw[0].length, newText: '' };
    if (first.text.startsWith('[')) {
        return [
            {
                title: 'Remove shell=True (arguments are already a list)',
                preferred: true,
                edits: [removeKw],
            },
        ];
    }
    const hasImport = /^\s*import\s+shlex\b|^\s*from\s+shlex\s+import/m.test(documentText);
    return [
        {
            title: 'Run without a shell: shlex.split(...) and remove shell=True',
            preferred: true,
            edits: [
                { start: first.start, end: first.end, newText: `shlex.split(${first.text})` },
                removeKw,
            ],
            addImport: hasImport ? undefined : 'import shlex',
        },
    ];
}

function yamlFixes(line: string): Fix[] {
    const call = findCall(line, 'yaml.load');
    if (!call) {
        return [];
    }
    const edits: LineEdit[] = [
        {
            start: call.nameStart,
            end: call.nameStart + 'yaml.load'.length,
            newText: 'yaml.safe_load',
        },
    ];
    // safe_load takes no Loader argument.
    for (let i = 1; i < call.args.length; i++) {
        if (/^Loader\s*=/.test(call.args[i].text)) {
            edits.push({ start: call.args[i - 1].end, end: call.args[i].end, newText: '' });
        }
    }
    return [{ title: 'Use yaml.safe_load', preferred: true, edits }];
}

function mathRandomFixes(line: string): Fix[] {
    const m = /Math\.random\s*\(\s*\)/.exec(line);
    if (!m) {
        return [];
    }
    return [
        {
            title: 'Use crypto.getRandomValues (cryptographically secure)',
            preferred: true,
            edits: [
                {
                    start: m.index,
                    end: m.index + m[0].length,
                    newText: '(crypto.getRandomValues(new Uint32Array(1))[0] / 4294967296)',
                },
            ],
        },
    ];
}

function cStringFixes(line: string): Fix[] {
    const fixes: Fix[] = [];
    const replaceCall = (
        name: string,
        title: string,
        build: (a: string[]) => string | undefined,
    ) => {
        const call = findCall(line, name);
        if (!call) {
            return;
        }
        const text = build(call.args.map((a) => a.text));
        if (text) {
            fixes.push({
                title,
                preferred: true,
                edits: [{ start: call.nameStart, end: call.close + 1, newText: text }],
            });
        }
    };
    replaceCall('strcpy', 'Use snprintf (destination must be an array)', ([d, s]) =>
        d && s ? `snprintf(${d}, sizeof(${d}), "%s", ${s})` : undefined,
    );
    replaceCall(
        'strcat',
        'Use strncat with the remaining space (destination must be an array)',
        ([d, s]) => (d && s ? `strncat(${d}, ${s}, sizeof(${d}) - strlen(${d}) - 1)` : undefined),
    );
    replaceCall('sprintf', 'Use snprintf (destination must be an array)', ([d, ...rest]) =>
        d && rest.length ? `snprintf(${d}, sizeof(${d}), ${rest.join(', ')})` : undefined,
    );
    replaceCall('gets', 'Use fgets (destination must be an array)', ([d]) =>
        d ? `fgets(${d}, sizeof(${d}), stdin)` : undefined,
    );
    return fixes;
}
