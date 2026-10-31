export type Severity = 'High' | 'Medium' | 'Low';

/** A single finding as emitted by the Go analyzer (1-based line numbers). */
export interface Finding {
    line: number;
    issue: string;
    severity: Severity;
}

export interface FileReport {
    /** Workspace-relative path, for display. */
    fileName: string;
    uri: string;
    findings: Finding[];
}

export const SEVERITY_RANK: Record<Severity, number> = { High: 3, Medium: 2, Low: 1 };

export function isSeverity(v: unknown): v is Severity {
    return v === 'High' || v === 'Medium' || v === 'Low';
}
