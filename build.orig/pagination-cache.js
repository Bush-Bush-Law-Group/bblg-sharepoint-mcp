import { randomBytes } from "node:crypto";
import { logger } from "./logger.js";
export const DEFAULT_PAGINATION_MAX_ENTRIES = 100;
export const DEFAULT_PAGINATION_TTL_MS = 15 * 60 * 1000;
export class PaginationCache {
    entries = new Map();
    maxEntries;
    ttlMs;
    now;
    constructor(options = {}) {
        this.maxEntries = options.maxEntries ?? DEFAULT_PAGINATION_MAX_ENTRIES;
        this.ttlMs = options.ttlMs ?? DEFAULT_PAGINATION_TTL_MS;
        this.now = options.now ?? Date.now;
    }
    get size() {
        return this.entries.size;
    }
    /** Stores a result set and returns the token that continues it. */
    issue(data, position, query) {
        const token = randomBytes(16).toString('hex');
        this.store(token, { data, position, query, timestamp: this.now() });
        return token;
    }
    /**
     * Replaces `token` with a fresh token for the same result set at `position`. The old token stops
     * working, so the result set is referenced by exactly one live token.
     */
    advance(token, position) {
        const entry = this.get(token);
        if (!entry)
            return null;
        this.entries.delete(token);
        return this.issue(entry.data, position, entry.query);
    }
    /** Returns the live entry for a token, or undefined when unknown or expired. Marks it recently used. */
    get(token) {
        const entry = this.entries.get(token);
        if (!entry)
            return undefined;
        if (this.now() - entry.timestamp > this.ttlMs) {
            this.entries.delete(token);
            return undefined;
        }
        // Map iteration is insertion-ordered: re-inserting moves the entry to the most-recent end.
        this.entries.delete(token);
        this.entries.set(token, entry);
        return entry;
    }
    delete(token) {
        this.entries.delete(token);
    }
    clear() {
        this.entries.clear();
    }
    /** Drops expired entries; returns how many were removed. */
    sweep() {
        const now = this.now();
        let removed = 0;
        for (const [token, entry] of this.entries) {
            if (now - entry.timestamp > this.ttlMs) {
                this.entries.delete(token);
                removed++;
            }
        }
        if (removed > 0)
            logger.debug(`Pagination cache: removed ${removed} expired continuation(s)`);
        return removed;
    }
    store(token, entry) {
        while (this.entries.size >= this.maxEntries) {
            const oldest = this.entries.keys().next().value;
            if (oldest === undefined)
                break;
            this.entries.delete(oldest);
            logger.debug('Pagination cache: evicted least recently used continuation');
        }
        this.entries.set(token, entry);
    }
}
