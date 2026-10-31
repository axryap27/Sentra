import * as vscode from 'vscode';
import { Severity, isSeverity } from './types';

export const CONFIG_SECTION = 'sentra';

export interface SentraConfig {
    enabled: boolean;
    autoScan: boolean;
    severityLevel: Severity;
    excludePatterns: string[];
    showStatusBar: boolean;
    maxFileSize: number;
    enableIncrementalScanning: boolean;
}

/** Read settings fresh each time so changes apply without reloading the window. */
export function getConfig(scope?: vscode.ConfigurationScope): SentraConfig {
    const c = vscode.workspace.getConfiguration(CONFIG_SECTION, scope);
    const severity = c.get<string>('severityLevel', 'Medium');
    return {
        enabled: c.get<boolean>('enabled', true),
        autoScan: c.get<boolean>('autoScan', true),
        severityLevel: isSeverity(severity) ? severity : 'Medium',
        excludePatterns: c.get<string[]>('excludePatterns', []),
        showStatusBar: c.get<boolean>('showStatusBar', true),
        maxFileSize: c.get<number>('maxFileSize', 1024 * 1024),
        enableIncrementalScanning: c.get<boolean>('enableIncrementalScanning', true),
    };
}
