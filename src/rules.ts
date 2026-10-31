/** Rule metadata for hovers, SARIF and the report. IDs match the Go engine (rules.go). */
export interface RuleInfo {
    id: string;
    cwe: string;
    title: string;
    description: string;
    remediation: string;
}

const RULES: RuleInfo[] = [
    {
        id: 'code_injection',
        cwe: 'CWE-94',
        title: 'Code injection',
        description:
            'Dynamic evaluation (eval, exec, new Function, setTimeout with a string) runs whatever code reaches it.',
        remediation:
            'Avoid evaluating strings. Use a parser (e.g. json.loads / JSON.parse, ast.literal_eval) or a dispatch table.',
    },
    {
        id: 'xss',
        cwe: 'CWE-79',
        title: 'Cross-site scripting',
        description:
            'Untrusted data is written into HTML without escaping, so a crafted value can run script in the page.',
        remediation:
            'Use textContent instead of innerHTML, or encode for the HTML context (e.g. ESAPI encodeForHTML, a templating engine with autoescaping).',
    },
    {
        id: 'buffer_overflow',
        cwe: 'CWE-120',
        title: 'Buffer overflow',
        description: 'The call copies or reads data without checking the destination size.',
        remediation:
            'Use bounded variants: snprintf, strncat with the remaining size, fgets instead of gets; check lengths before memcpy.',
    },
    {
        id: 'weak_crypto',
        cwe: 'CWE-327',
        title: 'Weak cryptography',
        description: 'MD5, SHA-1, DES, RC4 and ECB mode are broken or deprecated for security use.',
        remediation:
            'Use SHA-256 or better for hashing, a password KDF (bcrypt, scrypt, Argon2) for passwords, and AES-GCM for encryption.',
    },
    {
        id: 'unsafe_deserialization',
        cwe: 'CWE-502',
        title: 'Unsafe deserialization',
        description:
            'Deserializing untrusted data with pickle, yaml.load, ObjectInputStream and similar can execute arbitrary code.',
        remediation:
            'Use a data-only format (JSON) or a safe loader (yaml.safe_load); never deserialize data from untrusted sources.',
    },
    {
        id: 'hardcoded_secret',
        cwe: 'CWE-798',
        title: 'Hardcoded secret',
        description:
            'A credential appears to be embedded in source code, where it ends up in version control and builds.',
        remediation:
            'Load it from the environment or a secret manager, and rotate the exposed value.',
    },
    {
        id: 'command_injection',
        cwe: 'CWE-78',
        title: 'OS command injection',
        description: 'A shell command is built from data that may be attacker-controlled.',
        remediation:
            'Pass an argument list without a shell (subprocess.run([...]), execFile, ProcessBuilder with separate args) and validate inputs.',
    },
    {
        id: 'path_traversal',
        cwe: 'CWE-22',
        title: 'Path traversal',
        description:
            'A file path is built from user input, so "../" sequences can reach files outside the intended directory.',
        remediation:
            'Resolve the path and check it stays under an allowed base directory, or map user input to a fixed set of names.',
    },
    {
        id: 'memory_leak',
        cwe: 'CWE-401',
        title: 'Memory management',
        description: 'Memory is allocated in a function that never frees it.',
        remediation:
            'Free the allocation on every path, or transfer ownership explicitly; consider RAII/smart pointers in C++.',
    },
    {
        id: 'weak_randomness',
        cwe: 'CWE-330',
        title: 'Weak randomness',
        description:
            'This generator is predictable and must not be used for tokens, keys, passwords or session IDs.',
        remediation:
            'Use a CSPRNG: crypto.getRandomValues / crypto.randomUUID, secrets (Python), SecureRandom (Java).',
    },
    {
        id: 'sql_injection',
        cwe: 'CWE-89',
        title: 'SQL injection',
        description: 'A SQL statement is built dynamically, so data can change the query itself.',
        remediation:
            'Use parameterized queries / prepared statements with placeholders and pass values separately.',
    },
];

const BY_ID = new Map(RULES.map((r) => [r.id, r]));

export function ruleInfo(id: string | undefined): RuleInfo | undefined {
    return id ? BY_ID.get(id) : undefined;
}

export function allRules(): RuleInfo[] {
    return RULES;
}

export function cweUrl(cwe: string): string {
    return `https://cwe.mitre.org/data/definitions/${cwe.replace(/^CWE-/, '')}.html`;
}
