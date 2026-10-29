import crypto from 'crypto';
import fs from 'fs/promises';
import path from 'path';
import os from 'os';
import { logger } from './logger.js';
/**
 * Provides secure, encrypted token caching with automatic expiration
 * and machine-specific encryption keys
 */
export class EncryptedTokenCache {
    encryptionKey;
    cacheDir;
    tokenFileName;
    algorithm = 'aes-256-gcm';
    keyLength = 32;
    ivLength = 16;
    authTagLength = 16;
    constructor(cacheDir) {
        // Set cache directory with fallback to temp directory
        this.cacheDir = cacheDir || process.env.TOKEN_CACHE_DIR ||
            path.join(os.tmpdir(), '.mcp-sharepoint-cache');
        // Use a unique filename based on client ID if available
        const clientId = process.env.CLIENT_ID || 'default';
        this.tokenFileName = `token-${this.hashString(clientId)}.enc`;
        // Derive encryption key
        this.encryptionKey = this.deriveEncryptionKey();
        logger.info('Token cache initialized', {
            cacheDir: this.cacheDir,
            tokenFile: this.tokenFileName
        });
    }
    /**
     * Derives a machine-specific encryption key using scrypt
     */
    deriveEncryptionKey() {
        // Combine multiple factors for key derivation
        const factors = [
            os.hostname(),
            os.userInfo().username,
            process.env.TENANT_ID || 'default-tenant',
            process.env.CLIENT_ID || 'default-client'
        ];
        // Use environment secret if available, otherwise use machine-specific data
        const secret = process.env.CACHE_ENCRYPTION_SECRET;
        if (!secret) {
            logger.warn('SECURITY WARNING: CACHE_ENCRYPTION_SECRET not set. Token cache encryption uses machine-specific data which may be predictable. ' +
                'Set CACHE_ENCRYPTION_SECRET to a strong random value in production.');
        }
        const effectiveSecret = secret || factors.join(':');
        const salt = this.hashString(factors.join('|'));
        // Use scrypt for key derivation (resistant to GPU attacks)
        return crypto.scryptSync(effectiveSecret, salt, this.keyLength);
    }
    /**
     * Creates a SHA-256 hash of a string
     */
    hashString(input) {
        return crypto.createHash('sha256').update(input).digest('hex').substring(0, 16);
    }
    /**
     * Saves token data to encrypted cache file
     */
    async saveToken(token, expiresOn, scopes, metadata) {
        try {
            // Prepare token data
            const tokenData = {
                token,
                expiresOn: expiresOn.toISOString(),
                scopes,
                authMode: metadata?.authMode,
                tenantId: metadata?.tenantId,
                clientId: metadata?.clientId,
                cachedAt: new Date().toISOString()
            };
            // Generate random IV for this encryption
            const iv = crypto.randomBytes(this.ivLength);
            // Create cipher
            const cipher = crypto.createCipheriv(this.algorithm, this.encryptionKey, iv);
            // Encrypt the data
            const jsonData = JSON.stringify(tokenData);
            const encrypted = Buffer.concat([
                cipher.update(jsonData, 'utf8'),
                cipher.final()
            ]);
            // Get the authentication tag
            const authTag = cipher.getAuthTag();
            // Combine IV, auth tag, and encrypted data
            const payload = Buffer.concat([iv, authTag, encrypted]);
            // Ensure cache directory exists with restrictive permissions
            await fs.mkdir(this.cacheDir, { recursive: true, mode: 0o700 });
            // Write encrypted file with restrictive permissions
            const filePath = path.join(this.cacheDir, this.tokenFileName);
            await fs.writeFile(filePath, payload, { mode: 0o600 });
            logger.info('Token cached successfully', {
                expiresOn: expiresOn.toISOString(),
                scopeCount: scopes?.length || 0
            });
        }
        catch (error) {
            logger.error('Failed to cache token', error);
            // Don't throw - caching is a nice-to-have feature
        }
    }
    /**
     * Loads and decrypts token from cache
     */
    async loadToken() {
        try {
            const filePath = path.join(this.cacheDir, this.tokenFileName);
            // Check if file exists
            try {
                await fs.access(filePath);
            }
            catch {
                logger.debug('No cached token found');
                return null;
            }
            // Read encrypted file
            const payload = await fs.readFile(filePath);
            // Extract components
            const iv = payload.slice(0, this.ivLength);
            const authTag = payload.slice(this.ivLength, this.ivLength + this.authTagLength);
            const encrypted = payload.slice(this.ivLength + this.authTagLength);
            // Create decipher
            const decipher = crypto.createDecipheriv(this.algorithm, this.encryptionKey, iv);
            decipher.setAuthTag(authTag);
            // Decrypt
            const decrypted = Buffer.concat([
                decipher.update(encrypted),
                decipher.final()
            ]);
            // Parse JSON
            const tokenData = JSON.parse(decrypted.toString('utf8'));
            // Check expiration
            const expiresOn = new Date(tokenData.expiresOn);
            const now = new Date();
            // Add a 5-minute buffer before expiration
            const bufferMs = 5 * 60 * 1000;
            if (expiresOn.getTime() - bufferMs <= now.getTime()) {
                logger.info('Cached token expired or expiring soon', {
                    expiresOn: tokenData.expiresOn,
                    now: now.toISOString()
                });
                await this.clearCache();
                return null;
            }
            // Validate cached data matches current configuration
            if (tokenData.tenantId && process.env.TENANT_ID &&
                tokenData.tenantId !== process.env.TENANT_ID) {
                logger.info('Cached token tenant mismatch, clearing cache');
                await this.clearCache();
                return null;
            }
            if (tokenData.clientId && process.env.CLIENT_ID &&
                tokenData.clientId !== process.env.CLIENT_ID) {
                logger.info('Cached token client mismatch, clearing cache');
                await this.clearCache();
                return null;
            }
            logger.info('Loaded valid token from cache', {
                expiresOn: tokenData.expiresOn,
                cachedAt: tokenData.cachedAt,
                scopeCount: tokenData.scopes?.length || 0
            });
            return {
                token: tokenData.token,
                expiresOn,
                scopes: tokenData.scopes,
                metadata: {
                    authMode: tokenData.authMode,
                    tenantId: tokenData.tenantId,
                    clientId: tokenData.clientId
                }
            };
        }
        catch (error) {
            logger.error('Failed to load cached token', error);
            // Clear corrupted cache
            await this.clearCache();
            return null;
        }
    }
    /**
     * Clears the token cache
     */
    async clearCache() {
        try {
            const filePath = path.join(this.cacheDir, this.tokenFileName);
            await fs.unlink(filePath);
            logger.info('Token cache cleared');
        }
        catch (error) {
            // File might not exist, which is fine
            logger.debug('No cache to clear');
        }
    }
    /**
     * Checks if a cached token exists and is valid
     */
    async hasValidCache() {
        const cached = await this.loadToken();
        return cached !== null;
    }
    /**
     * Gets cache statistics (for debugging/monitoring)
     */
    async getCacheStats() {
        try {
            const filePath = path.join(this.cacheDir, this.tokenFileName);
            const stats = await fs.stat(filePath);
            // Try to get expiration from cached token
            const cached = await this.loadToken();
            return {
                exists: true,
                size: stats.size,
                modified: stats.mtime,
                expires: cached?.expiresOn
            };
        }
        catch {
            return { exists: false };
        }
    }
}
