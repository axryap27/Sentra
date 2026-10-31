import * as path from 'path';

/** Language identifiers understood by the Go analyzer's --lang flag. */
export type AnalyzerLanguage =
    | 'python'
    | 'javascript'
    | 'typescript'
    | 'java'
    | 'c'
    | 'cpp'
    | 'go'
    | 'php'
    | 'csharp'
    | 'rust';

const BY_EXTENSION: Record<string, AnalyzerLanguage> = {
    '.py': 'python',
    '.js': 'javascript',
    '.jsx': 'javascript',
    '.mjs': 'javascript',
    '.cjs': 'javascript',
    '.ts': 'typescript',
    '.tsx': 'typescript',
    '.java': 'java',
    '.c': 'c',
    '.h': 'cpp',
    '.cpp': 'cpp',
    '.cc': 'cpp',
    '.cxx': 'cpp',
    '.hpp': 'cpp',
    '.go': 'go',
    '.php': 'php',
    '.cs': 'csharp',
    '.rs': 'rust',
};

const BY_LANGUAGE_ID: Record<string, AnalyzerLanguage> = {
    python: 'python',
    javascript: 'javascript',
    javascriptreact: 'javascript',
    typescript: 'typescript',
    typescriptreact: 'typescript',
    java: 'java',
    c: 'c',
    cpp: 'cpp',
    go: 'go',
    php: 'php',
    csharp: 'csharp',
    rust: 'rust',
};

export const SUPPORTED_EXTENSIONS = Object.keys(BY_EXTENSION);

/** Glob matching every supported source file, for workspace.findFiles. */
export const SUPPORTED_GLOB = `**/*.{${SUPPORTED_EXTENSIONS.map((e) => e.slice(1)).join(',')}}`;

/** Resolve the analyzer language from a VS Code languageId, falling back to the file extension. */
export function resolveLanguage(
    languageId: string | undefined,
    fsPath: string,
): AnalyzerLanguage | undefined {
    if (languageId && BY_LANGUAGE_ID[languageId]) {
        return BY_LANGUAGE_ID[languageId];
    }
    return BY_EXTENSION[path.extname(fsPath).toLowerCase()];
}
