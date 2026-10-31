import * as assert from 'assert';
import { toSarif } from '../../sarif';

describe('toSarif', () => {
    it('produces a SARIF 2.1.0 log GitHub can ingest', () => {
        const log = toSarif(
            [
                {
                    relativePath: 'src/app.py',
                    findings: [
                        {
                            line: 4,
                            column: 3,
                            endLine: 4,
                            endColumn: 20,
                            rule: 'sql_injection',
                            cwe: 'CWE-89',
                            severity: 'High',
                            confidence: 0.81,
                            issue: 'SQL injection',
                        },
                    ],
                },
            ],
            '0.3.0',
        ) as {
            version: string;
            runs: {
                tool: { driver: { rules: { id: string; helpUri: string }[] } };
                results: Record<string, unknown>[];
            }[];
        };
        assert.strictEqual(log.version, '2.1.0');
        const run = log.runs[0];
        const result = run.results[0] as {
            ruleId: string;
            ruleIndex: number;
            level: string;
            locations: {
                physicalLocation: {
                    artifactLocation: { uri: string };
                    region: { startLine: number };
                };
            }[];
            properties: Record<string, string>;
        };
        assert.strictEqual(result.level, 'error');
        assert.strictEqual(run.tool.driver.rules[result.ruleIndex].id, 'sql_injection');
        assert.strictEqual(result.locations[0].physicalLocation.artifactLocation.uri, 'src/app.py');
        assert.strictEqual(result.locations[0].physicalLocation.region.startLine, 4);
        assert.strictEqual(result.properties['security-severity'], '8.0');
        assert.match(
            run.tool.driver.rules[result.ruleIndex].helpUri,
            /cwe\.mitre\.org\/data\/definitions\/89\.html/,
        );
    });
});
