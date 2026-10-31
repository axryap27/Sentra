import { createHash } from 'crypto';
import * as vscode from 'vscode';
import { Finding } from './types';

const STATE_KEY = 'sentra.resultCache.v1';
const MAX_ENTRIES = 5000;

/**
 * Content-addressed cache of analyzer results: key = sha256(engine version, language,
 * content). Unchanged files are never re-analyzed, and editing a file back to a
 * previous state is a cache hit. Bounded (LRU by insertion order) and stored per
 * workspace rather than globally.
 */
export class ResultCache {
    private readonly entries: Map<string, Finding[]>;
    private dirty = false;

    constructor(
        private readonly state: vscode.Memento,
        private readonly engineVersion: string,
    ) {
        const saved = state.get<[string, Finding[]][]>(STATE_KEY, []);
        this.entries = new Map(Array.isArray(saved) ? saved : []);
    }

    key(language: string, content: string): string {
        return createHash('sha256')
            .update(this.engineVersion)
            .update('\0')
            .update(language)
            .update('\0')
            .update(content)
            .digest('hex');
    }

    get(key: string): Finding[] | undefined {
        const hit = this.entries.get(key);
        if (hit) {
            // refresh recency
            this.entries.delete(key);
            this.entries.set(key, hit);
        }
        return hit;
    }

    set(key: string, findings: Finding[]): void {
        this.entries.delete(key);
        this.entries.set(key, findings);
        while (this.entries.size > MAX_ENTRIES) {
            const oldest = this.entries.keys().next().value;
            if (oldest === undefined) {
                break;
            }
            this.entries.delete(oldest);
        }
        this.dirty = true;
    }

    clear(): void {
        this.entries.clear();
        this.dirty = true;
    }

    async flush(): Promise<void> {
        if (this.dirty) {
            this.dirty = false;
            await this.state.update(STATE_KEY, [...this.entries]);
        }
    }
}
