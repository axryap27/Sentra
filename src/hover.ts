import * as vscode from 'vscode';
import { cweUrl, ruleInfo } from './rules';
import { Finding } from './types';

/** Explains Sentra findings under the cursor: rule, CWE link, why it matters, how to fix. */
export class SentraHover implements vscode.HoverProvider {
    constructor(private readonly findingsFor: (uri: vscode.Uri) => Finding[]) {}

    provideHover(doc: vscode.TextDocument, pos: vscode.Position): vscode.Hover | undefined {
        const here = this.findingsFor(doc.uri).filter((f) => f.line - 1 === pos.line);
        if (!here.length) {
            return undefined;
        }
        const md = new vscode.MarkdownString(undefined, true);
        for (const f of here) {
            const info = ruleInfo(f.rule);
            const cwe = f.cwe ?? info?.cwe;
            md.appendMarkdown(`**$(shield) Sentra: ${info?.title ?? f.rule ?? 'Security issue'}**`);
            if (cwe) {
                md.appendMarkdown(` · [${cwe}](${cweUrl(cwe)})`);
            }
            md.appendMarkdown(` · ${f.severity}`);
            if (typeof f.confidence === 'number') {
                md.appendMarkdown(` · confidence ${Math.round(f.confidence * 100)}%`);
            }
            md.appendMarkdown('\n\n');
            if (info) {
                md.appendMarkdown(`${info.description}\n\n**Fix:** ${info.remediation}\n\n`);
            }
            if (f.rule) {
                md.appendMarkdown(
                    `Suppress with a \`sentra-ignore: ${f.rule}\` comment on this line.\n\n`,
                );
            }
        }
        return new vscode.Hover(md);
    }
}
