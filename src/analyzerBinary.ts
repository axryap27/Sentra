import * as fs from 'fs';
import * as path from 'path';

const EXE = process.platform === 'win32' ? 'sentra-analyzer.exe' : 'sentra-analyzer';

/**
 * Locate the prebuilt analyzer shipped in the VSIX (bin/<platform>-<arch>/), falling
 * back to a local development build (bin/local/, produced by `make go-build`).
 * The extension never compiles Go at runtime.
 */
export function findAnalyzerBinary(extensionPath: string): string | undefined {
    const candidates = [
        path.join(extensionPath, 'bin', `${process.platform}-${process.arch}`, EXE),
        path.join(extensionPath, 'bin', 'local', EXE),
    ];
    return candidates.find((p) => fs.existsSync(p));
}

export type AnalyzerErrorKind = 'missing-binary' | 'crash' | 'timeout' | 'bad-output';

export class AnalyzerError extends Error {
    constructor(
        readonly kind: AnalyzerErrorKind,
        message: string,
    ) {
        super(message);
        this.name = 'AnalyzerError';
    }
}
