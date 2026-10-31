import { allRules, cweUrl, ruleInfo } from './rules';
import { Finding } from './types';

/** One file's findings with a path relative to the workspace root (forward slashes). */
export interface SarifInput {
    relativePath: string;
    findings: Finding[];
}

const LEVEL = { High: 'error', Medium: 'warning', Low: 'note' } as const;
const SECURITY_SEVERITY = { High: '8.0', Medium: '5.0', Low: '2.0' } as const;

/**
 * Build a SARIF 2.1.0 log accepted by GitHub code scanning (upload with
 * github/codeql-action/upload-sarif). security-severity drives GitHub's severity labels.
 */
export function toSarif(files: SarifInput[], version: string): object {
    const rules = allRules().map((r) => ({
        id: r.id,
        name: r.title.replace(/[^A-Za-z0-9]+(.)?/g, (_m, c: string | undefined) =>
            c ? c.toUpperCase() : '',
        ),
        shortDescription: { text: r.title },
        fullDescription: { text: r.description },
        help: { text: r.remediation, markdown: `${r.remediation}\n\n[${r.cwe}](${cweUrl(r.cwe)})` },
        helpUri: cweUrl(r.cwe),
        properties: {
            tags: ['security', `external/cwe/${r.cwe.toLowerCase()}`],
            precision: 'medium',
        },
    }));
    const results = files.flatMap((file) =>
        file.findings.map((f) => {
            const rule = f.rule ?? 'unknown';
            return {
                ruleId: rule,
                ruleIndex: rules.findIndex((r) => r.id === rule),
                level: LEVEL[f.severity],
                message: { text: f.issue },
                locations: [
                    {
                        physicalLocation: {
                            artifactLocation: {
                                uri: encodeURI(file.relativePath),
                                uriBaseId: '%SRCROOT%',
                            },
                            region: {
                                startLine: f.line,
                                startColumn: f.column ?? 1,
                                ...(f.endLine ? { endLine: f.endLine } : {}),
                                ...(f.endColumn ? { endColumn: f.endColumn } : {}),
                            },
                        },
                    },
                ],
                properties: {
                    'security-severity': SECURITY_SEVERITY[f.severity],
                    ...(typeof f.confidence === 'number' ? { confidence: f.confidence } : {}),
                    ...(ruleInfo(rule) ? { cwe: ruleInfo(rule)!.cwe } : {}),
                },
            };
        }),
    );
    return {
        $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
        version: '2.1.0',
        runs: [
            {
                tool: {
                    driver: {
                        name: 'Sentra',
                        version,
                        informationUri: 'https://github.com/axryap27/sentra',
                        rules,
                    },
                },
                originalUriBaseIds: { '%SRCROOT%': { description: { text: 'Workspace root' } } },
                results,
            },
        ],
    };
}
