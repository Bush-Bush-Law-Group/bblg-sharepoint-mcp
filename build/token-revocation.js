/**
 * Token Revocation List (TRL) Manager
 *
 * Provides ability to revoke tokens before their expiration
 * Critical for handling compromised tokens and emergency scenarios
 */
import { logger } from './logger.js';
import crypto from 'crypto';
import path from 'path';
import { readStateFile, writeStateFile, resolveStateDir, UnsafeStateFileError } from './state-file.js';
const SHA256_HEX = /^[0-9a-f]{64}$/;
function requiredDate(value) {
    if (typeof value !== 'string' && typeof value !== 'number')
        return null;
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date;
}
/** One persisted entry, rebuilt field by field; null when it does not match the schema. */
function parseRevokedToken(key, value) {
    if (!SHA256_HEX.test(key) || !value || typeof value !== 'object' || Array.isArray(value))
        return null;
    const record = value;
    if (record.tokenHash !== key || typeof record.reason !== 'string')
        return null;
    if (record.revokedBy !== undefined && typeof record.revokedBy !== 'string')
        return null;
    const revokedAt = requiredDate(record.revokedAt);
    const expiresAt = requiredDate(record.expiresAt);
    if (!revokedAt || !expiresAt)
        return null;
    return { tokenHash: key, revokedAt, expiresAt, reason: record.reason, revokedBy: record.revokedBy };
}
/**
 * Parses a persisted revocation list. Returns null when the document itself is not a
 * hash-keyed object; otherwise the valid entries plus a count of entries that were dropped.
 * Valid entries are kept even when others are malformed, so corruption never un-revokes a token.
 */
export function parsePersistedRevocationList(raw) {
    let parsed;
    try {
        parsed = JSON.parse(raw);
    }
    catch {
        return null;
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed))
        return null;
    const entries = new Map();
    let dropped = 0;
    for (const [key, value] of Object.entries(parsed)) {
        const entry = parseRevokedToken(key, value);
        if (entry)
            entries.set(key, entry);
        else
            dropped++;
    }
    return { entries, dropped };
}
export class TokenRevocationManager {
    static instance;
    revokedTokens = new Map();
    persistencePath;
    cleanupInterval;
    loaded;
    constructor() {
        // Persist in a per-user private directory, never a world-writable one.
        this.persistencePath = path.join(resolveStateDir(process.env.TOKEN_REVOCATION_DIR, process.env.LOG_DIR), 'token-revocation-list.json');
        // Load persisted revocations. Never rejects; callers await ready() before trusting isRevoked.
        this.loaded = this.loadRevocationList();
        // Clean up expired revocations every hour
        this.cleanupInterval = setInterval(() => {
            this.cleanupExpiredRevocations();
        }, 60 * 60 * 1000);
        this.cleanupInterval.unref?.();
        logger.info('Token Revocation Manager initialized', {
            persistencePath: this.persistencePath
        });
    }
    static getInstance() {
        if (!TokenRevocationManager.instance) {
            TokenRevocationManager.instance = new TokenRevocationManager();
        }
        return TokenRevocationManager.instance;
    }
    /** Resolves once the persisted list has been read (or rejected). Await before the first isRevoked. */
    ready() {
        return this.loaded;
    }
    /**
     * Revoke a token
     * @param token The token to revoke
     * @param reason Reason for revocation
     * @param expiresAt When the token naturally expires (for cleanup)
     * @param revokedBy Who initiated the revocation
     */
    async revokeToken(token, reason, expiresAt, revokedBy) {
        const tokenHash = this.hashToken(token);
        const revokedToken = {
            tokenHash,
            revokedAt: new Date(),
            reason,
            revokedBy,
            expiresAt: expiresAt || new Date(Date.now() + 24 * 60 * 60 * 1000) // Default 24h
        };
        this.revokedTokens.set(tokenHash, revokedToken);
        // Persist to disk
        await this.saveRevocationList();
        // Audit log
        logger.audit('TOKEN_REVOKED', {
            action: 'REVOKE',
            result: 'SUCCESS',
            targetResource: 'token',
            metadata: {
                tokenHash: tokenHash.substring(0, 8) + '...',
                reason,
                revokedBy,
                expiresAt: revokedToken.expiresAt
            }
        });
        logger.warn('Token revoked', {
            tokenHash: tokenHash.substring(0, 8) + '...',
            reason,
            revokedBy
        });
    }
    /**
     * Check if a token is revoked
     * @param token The token to check
     * @returns true if revoked, false otherwise
     */
    isRevoked(token) {
        const tokenHash = this.hashToken(token);
        const revocation = this.revokedTokens.get(tokenHash);
        if (revocation) {
            logger.info('Revoked token access attempted', {
                tokenHash: tokenHash.substring(0, 8) + '...',
                reason: revocation.reason,
                revokedAt: revocation.revokedAt
            });
            return true;
        }
        return false;
    }
    /**
     * Bulk revoke tokens (e.g., for a compromised user)
     * @param tokens Array of tokens to revoke
     * @param reason Reason for bulk revocation
     */
    async bulkRevoke(tokens, reason) {
        for (const token of tokens) {
            await this.revokeToken(token, reason, undefined, 'bulk_operation');
        }
        logger.warn('Bulk token revocation completed', {
            count: tokens.length,
            reason
        });
    }
    /**
     * Clear all revocations (emergency reset)
     */
    async clearAllRevocations() {
        const count = this.revokedTokens.size;
        this.revokedTokens.clear();
        await this.saveRevocationList();
        logger.audit('TOKEN_REVOCATION_CLEARED', {
            action: 'CLEAR_ALL',
            result: 'SUCCESS',
            targetResource: 'revocation_list',
            metadata: { clearedCount: count }
        });
    }
    /**
     * Get revocation statistics
     */
    getStats() {
        const now = Date.now();
        const active = Array.from(this.revokedTokens.values()).filter(r => r.expiresAt.getTime() > now);
        return {
            totalRevoked: this.revokedTokens.size,
            activeRevocations: active.length,
            reasons: this.groupByReason(),
            oldestRevocation: this.getOldestRevocation(),
            persistencePath: this.persistencePath
        };
    }
    /**
     * Hash token for storage (we don't store actual tokens)
     */
    hashToken(token) {
        return crypto
            .createHash('sha256')
            .update(token)
            .digest('hex');
    }
    /**
     * Load revocation list from disk
     */
    async loadRevocationList() {
        let data;
        try {
            data = await readStateFile(this.persistencePath);
        }
        catch (error) {
            if (error instanceof UnsafeStateFileError) {
                logger.error('Refusing to read token revocation list', { path: this.persistencePath, reason: error.message });
            }
            else {
                logger.error('Error loading revocation list', error);
            }
            return;
        }
        if (data === null) {
            // File doesn't exist yet, that's ok
            logger.debug('No existing revocation list found');
            return;
        }
        const parsed = parsePersistedRevocationList(data);
        if (!parsed) {
            logger.warn('Ignoring invalid token revocation list', { path: this.persistencePath });
            return;
        }
        if (parsed.dropped > 0) {
            logger.warn('Dropped invalid entries from the token revocation list', { path: this.persistencePath, dropped: parsed.dropped });
        }
        for (const [hash, revocation] of parsed.entries) {
            this.revokedTokens.set(hash, revocation);
        }
        logger.info('Token revocation list loaded', {
            count: this.revokedTokens.size
        });
        // Clean up expired entries immediately
        this.cleanupExpiredRevocations();
    }
    /**
     * Save revocation list to disk
     */
    async saveRevocationList() {
        try {
            const data = Object.fromEntries(this.revokedTokens);
            await writeStateFile(this.persistencePath, JSON.stringify(data, null, 2));
        }
        catch (error) {
            if (error instanceof UnsafeStateFileError) {
                logger.error('Refusing to write token revocation list', { path: this.persistencePath, reason: error.message });
            }
            else {
                logger.error('Failed to save revocation list', error);
            }
        }
    }
    /**
     * Clean up expired revocations
     */
    cleanupExpiredRevocations() {
        const now = Date.now();
        let removed = 0;
        for (const [hash, revocation] of this.revokedTokens.entries()) {
            if (revocation.expiresAt.getTime() < now) {
                this.revokedTokens.delete(hash);
                removed++;
            }
        }
        if (removed > 0) {
            logger.info('Cleaned up expired revocations', { removed });
            this.saveRevocationList().catch(err => {
                logger.error('Failed to save after cleanup', err);
            });
        }
    }
    /**
     * Group revocations by reason for stats
     */
    groupByReason() {
        const groups = {};
        for (const revocation of this.revokedTokens.values()) {
            groups[revocation.reason] = (groups[revocation.reason] || 0) + 1;
        }
        return groups;
    }
    /**
     * Get oldest revocation
     */
    getOldestRevocation() {
        let oldest = null;
        for (const revocation of this.revokedTokens.values()) {
            if (!oldest || revocation.revokedAt < oldest) {
                oldest = revocation.revokedAt;
            }
        }
        return oldest;
    }
    /**
     * Emergency revoke all tokens for a specific user/tenant
     * (Requires external tracking of token->user mapping)
     */
    async emergencyRevokeByPattern(pattern, reason) {
        // This would require token metadata tracking
        // For now, log the emergency request
        logger.audit('EMERGENCY_REVOCATION_REQUEST', {
            action: 'EMERGENCY_REVOKE',
            result: 'SUCCESS', // Request logged successfully
            targetResource: pattern,
            metadata: { reason }
        });
        logger.error('Emergency revocation requested', {
            pattern,
            reason,
            note: 'Manual token revocation required'
        });
        return 0;
    }
    /**
     * Cleanup on shutdown
     */
    destroy() {
        if (this.cleanupInterval) {
            clearInterval(this.cleanupInterval);
        }
    }
}
// Export singleton instance
export const tokenRevocationManager = TokenRevocationManager.getInstance();
