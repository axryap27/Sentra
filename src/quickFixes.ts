import * as vscode from 'vscode';
import { Fix, fixesFor, suppressFix } from './fixes';

/** The rule ID stored on a Sentra diagnostic. */
export function diagnosticRule(d: vscode.Diagnostic): string | undefined {
    if (d.source !== 'Sentra') {
        return undefined;
    }
    const code = typeof d.code === 'object' ? d.code.value : d.code;
    return code === undefined ? undefined : String(code);
}

export class SentraCodeActions implements vscode.CodeActionProvider {
    static readonly kinds = [vscode.CodeActionKind.QuickFix];

    provideCodeActions(
        doc: vscode.TextDocument,
        _range: vscode.Range,
        ctx: vscode.CodeActionContext,
    ): vscode.CodeAction[] {
        const actions: vscode.CodeAction[] = [];
        for (const d of ctx.diagnostics) {
            const rule = diagnosticRule(d);
            if (!rule) {
                continue;
            }
            const line = doc.lineAt(d.range.start.line);
            for (const fix of fixesFor(rule, line.text, doc.languageId, doc.getText())) {
                actions.push(toAction(doc, line, fix, d));
            }
            actions.push(toAction(doc, line, suppressFix(line.text, rule, doc.languageId), d));
        }
        return actions;
    }
}

function toAction(
    doc: vscode.TextDocument,
    line: vscode.TextLine,
    fix: Fix,
    diagnostic: vscode.Diagnostic,
): vscode.CodeAction {
    const action = new vscode.CodeAction(fix.title, vscode.CodeActionKind.QuickFix);
    action.diagnostics = [diagnostic];
    action.isPreferred = fix.preferred;
    const edit = new vscode.WorkspaceEdit();
    for (const e of fix.edits) {
        edit.replace(
            doc.uri,
            new vscode.Range(line.lineNumber, e.start, line.lineNumber, e.end),
            e.newText,
        );
    }
    if (fix.addImport) {
        edit.insert(doc.uri, new vscode.Position(importLine(doc), 0), fix.addImport + '\n');
    }
    action.edit = edit;
    return action;
}

/** First line after a shebang, encoding line, module docstring and leading comments. */
function importLine(doc: vscode.TextDocument): number {
    let i = 0;
    while (i < doc.lineCount) {
        const t = doc.lineAt(i).text.trim();
        if (t.startsWith('#') || t === '') {
            i++;
            continue;
        }
        if (t.startsWith('"""') || t.startsWith("'''")) {
            const q = t.slice(0, 3);
            if (t.length > 3 && t.endsWith(q)) {
                i++;
                continue;
            }
            i++;
            while (i < doc.lineCount && !doc.lineAt(i).text.includes(q)) {
                i++;
            }
            i++;
            continue;
        }
        break;
    }
    return Math.min(i, doc.lineCount);
}
