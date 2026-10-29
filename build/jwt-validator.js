import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import * as jwksRsa from 'jwks-rsa';
import { logger } from './logger.js';
/**
 * The only audiences a pasted token may carry: Microsoft Graph by URI (v1 tokens) or by its
 * application ID (v2 tokens). A token minted for the MCP app itself is not a Graph token and
 * is refused, whatever CLIENT_ID is.
 */
export const GRAPH_AUDIENCES = [
    'https://graph.microsoft.com',
    '00000003-0000-0000-c000-000000000000',
];
/**
 * Secure JWT validator for Azure AD tokens
 * Implements proper signature verification and claim validation
 */
export class JwtValidator {
    jwksClient;
    validationOptions;
    tokenCache = new Map();
    hashToken(token) {
        return crypto.createHash('sha256').update(token).digest('hex');
    }
    constructor(options) {
        if (!options?.tenantId) {
            throw new Error('JwtValidator requires tenantId: tokens are accepted from one configured tenant only');
        }
        this.validationOptions = { tenantId: options.tenantId };
        // Initialize JWKS client for Azure AD
        this.jwksClient = new jwksRsa.JwksClient({
            jwksUri: 'https://login.microsoftonline.com/common/discovery/v2.0/keys',
            cache: true,
            cacheMaxEntries: 5,
            cacheMaxAge: 600000, // 10 minutes
            rateLimit: true,
            jwksRequestsPerMinute: 10
        });
        // Clean up expired cache entries every 5 minutes
        setInterval(() => this.cleanupCache(), 300000).unref?.();
    }
    /**
     * Validates and decodes a JWT token with full security checks
     * @param token The JWT token to validate
     * @returns Decoded and validated token claims
     * @throws Error if token is invalid
     */
    async validateToken(token) {
        try {
            // Check cache first
            const cached = this.tokenCache.get(this.hashToken(token));
            if (cached && cached.expires > Date.now()) {
                logger.debug('Returning cached validated token');
                return cached.token;
            }
            // Get the signing key from Azure AD
            const decodedHeader = jwt.decode(token, { complete: true });
            if (!decodedHeader) {
                throw new Error('Invalid token format');
            }
            const kid = decodedHeader.header.kid;
            if (!kid) {
                throw new Error('Token missing key ID (kid)');
            }
            const key = await this.getSigningKey(kid);
            // Verify the token with the public key
            const decoded = await this.verifyToken(token, key);
            // Additional validation checks
            this.validateClaims(decoded);
            // Cache the validated token
            this.tokenCache.set(this.hashToken(token), {
                token: decoded,
                expires: decoded.exp * 1000
            });
            logger.info('Token validated successfully', {
                subject: decoded.sub,
                issuer: decoded.iss,
                audience: decoded.aud,
                scopes: this.extractScopes(decoded)
            });
            return decoded;
        }
        catch (error) {
            logger.error('Token validation failed', error);
            throw new Error(`Token validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
    /**
     * Extracts scopes from a validated token
     * @param token The JWT token to parse
     * @returns Array of scopes
     */
    async extractScopes(token) {
        try {
            let decoded;
            if (typeof token === 'string') {
                // Validate the token first
                decoded = await this.validateToken(token);
            }
            else {
                decoded = token;
            }
            // Extract scopes from 'scp' claim (delegated permissions)
            if (decoded.scp && typeof decoded.scp === 'string') {
                return decoded.scp.split(' ').filter(scope => scope.length > 0);
            }
            // Extract from 'roles' claim (application permissions)
            if (decoded.roles && Array.isArray(decoded.roles)) {
                return decoded.roles;
            }
            return [];
        }
        catch (error) {
            logger.error('Failed to extract scopes from token', error);
            return [];
        }
    }
    /**
     * Gets the signing key from Azure AD JWKS endpoint
     */
    async getSigningKey(kid) {
        return new Promise((resolve, reject) => {
            this.jwksClient.getSigningKey(kid, (err, key) => {
                if (err) {
                    reject(err);
                }
                else if (key) {
                    const signingKey = 'publicKey' in key ? key.publicKey : key.rsaPublicKey;
                    if (signingKey) {
                        resolve(signingKey);
                    }
                    else {
                        reject(new Error('Unable to extract signing key'));
                    }
                }
                else {
                    reject(new Error('No signing key found'));
                }
            });
        });
    }
    /**
     * Verifies the JWT signature and returns decoded claims. Issuer and audience are always
     * enforced: the token must come from the configured tenant and be minted for Microsoft Graph.
     */
    async verifyToken(token, publicKey) {
        return new Promise((resolve, reject) => {
            const { tenantId } = this.validationOptions;
            const options = {
                algorithms: ['RS256'],
                complete: false,
                issuer: [
                    `https://sts.windows.net/${tenantId}/`,
                    `https://login.microsoftonline.com/${tenantId}/v2.0`
                ],
                audience: [...GRAPH_AUDIENCES],
            };
            jwt.verify(token, publicKey, options, (err, decoded) => {
                if (err) {
                    reject(err);
                }
                else {
                    resolve(decoded);
                }
            });
        });
    }
    /**
     * Performs additional claim validation
     */
    validateClaims(decoded) {
        const now = Math.floor(Date.now() / 1000);
        // Check token expiration
        if (decoded.exp <= now) {
            throw new Error('Token has expired');
        }
        // Check not before time
        if (decoded.nbf && decoded.nbf > now) {
            throw new Error('Token not yet valid');
        }
        // Validate token version (Azure AD specific)
        if (decoded.ver && decoded.ver !== '1.0' && decoded.ver !== '2.0') {
            throw new Error(`Unsupported token version: ${decoded.ver}`);
        }
        // The tid claim must name the configured tenant; a missing tid is a mismatch, not a pass.
        if (decoded.tid !== this.validationOptions.tenantId) {
            throw new Error('Token tenant mismatch');
        }
        // Check for required claims
        if (!decoded.sub && !decoded.oid) {
            throw new Error('Token missing subject identifier');
        }
    }
    /**
     * Cleans up expired tokens from cache
     */
    cleanupCache() {
        const now = Date.now();
        for (const [key, value] of this.tokenCache.entries()) {
            if (value.expires <= now) {
                this.tokenCache.delete(key);
            }
        }
    }
    /**
     * Checks if a token has the required scopes
     */
    async hasRequiredScopes(token, requiredScopes) {
        try {
            const scopes = await this.extractScopes(token);
            return requiredScopes.every(required => scopes.some(scope => scope === required ||
                scope === 'Directory.ReadWrite.All' || // Admin scope covers most operations
                (required.includes('.Read') && scope === required.replace('.Read', '.ReadWrite'))));
        }
        catch (error) {
            logger.error('Failed to check required scopes', error);
            return false;
        }
    }
    /**
     * Updates validation options (useful for runtime configuration changes)
     */
    updateOptions(options) {
        if (options.tenantId !== undefined && !options.tenantId) {
            throw new Error('JwtValidator requires tenantId: tokens are accepted from one configured tenant only');
        }
        this.validationOptions = { ...this.validationOptions, ...options };
        // Clear cache when options change
        this.tokenCache.clear();
    }
}
