import { logger } from "./logger.js";
import { readPositiveInt } from "./constants.js";
class RateLimiter {
    limits = new Map();
    maxRequests;
    windowMs;
    constructor(maxRequests = 100, windowMs = 60000) {
        this.maxRequests = readPositiveInt('RATE_LIMIT_MAX', maxRequests, { min: 1, max: 1_000_000 });
        this.windowMs = readPositiveInt('RATE_LIMIT_WINDOW_MS', windowMs, { min: 1000, max: 24 * 60 * 60 * 1000 });
        // Cleanup old entries every minute
        setInterval(() => this.cleanup(), 60000).unref?.();
    }
    isAllowed(identifier) {
        const now = Date.now();
        const entry = this.limits.get(identifier);
        if (!entry || now > entry.resetTime) {
            // New window
            this.limits.set(identifier, {
                count: 1,
                resetTime: now + this.windowMs
            });
            return true;
        }
        if (entry.count >= this.maxRequests) {
            logger.warn(`Rate limit exceeded for ${identifier}`, {
                count: entry.count,
                maxRequests: this.maxRequests
            });
            return false;
        }
        entry.count++;
        return true;
    }
    cleanup() {
        const now = Date.now();
        for (const [key, entry] of this.limits.entries()) {
            if (now > entry.resetTime) {
                this.limits.delete(key);
            }
        }
    }
    getRemainingRequests(identifier) {
        const entry = this.limits.get(identifier);
        if (!entry || Date.now() > entry.resetTime) {
            return this.maxRequests;
        }
        return Math.max(0, this.maxRequests - entry.count);
    }
}
// Permission validation
export class PermissionValidator {
    static SENSITIVE_OPERATIONS = [
        'POST',
        'PUT',
        'PATCH',
        'DELETE'
    ];
    static DANGEROUS_PATHS = [
        '/roleManagement',
        '/privilegedAccess',
        '/conditionalAccess',
        '/policies',
        '/applications',
        '/servicePrincipals',
        '/oauth2PermissionGrants',
        '/appRoleAssignments'
    ];
    static REQUIRED_SCOPES_MAP = {
        '/users': ['User.Read.All', 'User.ReadWrite.All', 'Directory.Read.All', 'Directory.ReadWrite.All'],
        '/groups': ['Group.Read.All', 'Group.ReadWrite.All', 'Directory.Read.All', 'Directory.ReadWrite.All'],
        '/applications': ['Application.Read.All', 'Application.ReadWrite.All', 'Directory.Read.All'],
        '/devices': ['Device.Read.All', 'Device.ReadWrite.All', 'Directory.Read.All'],
        '/roleManagement': ['RoleManagement.Read.All', 'RoleManagement.ReadWrite.Directory'],
        '/auditLogs': ['AuditLog.Read.All', 'Directory.Read.All'],
        '/identity/conditionalAccess': ['ConditionalAccess.Read.All', 'ConditionalAccess.ReadWrite.All', 'Policy.Read.All'],
        '/sites': ['Sites.Read.All', 'Sites.ReadWrite.All', 'Sites.Manage.All'],
        '/drives': ['Files.Read.All', 'Files.ReadWrite.All', 'Sites.ReadWrite.All', 'Sites.Manage.All', 'Sites.FullControl.All'],
    };
    /**
     * Scope families that Directory.Read.All / Directory.ReadWrite.All genuinely cover. Files.* and
     * Sites.* are content permissions and are never implied by a directory permission.
     */
    static DIRECTORY_FAMILIES = ['User.', 'Group.', 'Application.', 'Device.', 'AuditLog.', 'Directory.', 'ConditionalAccess.', 'Policy.'];
    // Anchored to the permission segment: "RoleManagement.Read.All" is a READ scope even though its
    // resource name contains "Manage". Graph scopes are Resource.Permission[.Qualifier].
    static WRITE_SCOPE = /\.(ReadWrite|Manage|FullControl)(\.|$)/i;
    /**
     * Matching is done on the path as it reaches Graph: the URL parser that sends the request
     * resolves `.`/`..` segments (in plain or %2e form) and Graph percent-decodes each segment, so
     * `/users/../roleManagement` and `/%72oleManagement` are both `/roleManagement` on the wire.
     * Graph paths are also case-insensitive and may carry a version prefix or query options, so the
     * result is lower-cased with `/v1.0` or `/beta` and anything after `?`/`#` removed.
     */
    static normalizePath(path) {
        let normalized = path.trim();
        const cut = normalized.search(/[?#]/);
        if (cut >= 0)
            normalized = normalized.slice(0, cut);
        if (!normalized.startsWith('/'))
            normalized = `/${normalized}`;
        try {
            normalized = new URL(normalized, 'https://graph.microsoft.com').pathname;
        }
        catch {
            // Unparseable input keeps its literal form; the schema has already refused it upstream.
        }
        normalized = normalized
            .split('/')
            .map(segment => {
            try {
                return decodeURIComponent(segment);
            }
            catch {
                return segment; // malformed escape: Graph would reject it, match it literally
            }
        })
            .join('/');
        normalized = normalized.replace(/^\/(v1\.0|beta)(?=\/|$)/i, '');
        if (!normalized.startsWith('/'))
            normalized = `/${normalized}`;
        return normalized.toLowerCase();
    }
    static validateScopes(path, method, scopes) {
        // Check if STRICT_PERMISSION_MODE is enabled
        const strictMode = process.env.STRICT_PERMISSION_MODE === 'true';
        if (!strictMode) {
            // In non-strict mode, just log a warning for sensitive operations
            if (this.isSensitiveOperation(method, path)) {
                logger.warn('Sensitive operation attempted', { path, method, scopes });
            }
            return { allowed: true };
        }
        // Find required scopes for the path
        const normalizedPath = this.normalizePath(path);
        const match = this.getRequiredScopes(normalizedPath);
        if (!match) {
            // No specific requirements, but check for dangerous operations
            return this.checkDangerousOperation(normalizedPath, path, method, scopes) ?? { allowed: true };
        }
        const { pattern: matchedPattern, scopes: requiredScopes } = match;
        // Check if user has at least one of the required scopes
        const hasRequiredScope = requiredScopes.some(reqScope => scopes.some(userScope => userScope === reqScope || this.isScopeSufficient(userScope, reqScope)));
        if (!hasRequiredScope) {
            return {
                allowed: false,
                reason: `Missing required scope for ${path}`,
                requiredScopes
            };
        }
        // Additional check for write operations: the write scope must come from the same resource
        // family as the path. A Files.ReadWrite.All token must not unlock a POST to /users.
        if (this.isSensitiveOperation(method, path)) {
            const writeScopes = requiredScopes.filter(s => this.WRITE_SCOPE.test(s));
            const hasWriteScope = writeScopes.some(reqScope => scopes.some(userScope => userScope === reqScope || this.isScopeSufficient(userScope, reqScope)));
            if (!hasWriteScope) {
                return {
                    allowed: false,
                    reason: `Write operation requires ReadWrite scope for ${path}`,
                    requiredScopes: writeScopes
                };
            }
            // A dangerous segment under an ordinary resource (e.g. /users/{id}/appRoleAssignments) is
            // still a privilege change: the matched entry's write scope is not enough on its own. When
            // the matched entry is itself the dangerous resource (/roleManagement, /applications), its
            // own scope list already names the right permission and governs alone.
            if (!this.isDangerousPath(matchedPattern.toLowerCase())) {
                const denied = this.checkDangerousOperation(normalizedPath, path, method, scopes);
                if (denied)
                    return denied;
            }
        }
        return { allowed: true };
    }
    /**
     * A write to a dangerous path requires Directory.ReadWrite.All. Returns the refusal, or
     * undefined when the operation is not dangerous or the scope is present.
     * `normalizedPath` must come from normalizePath().
     */
    static checkDangerousOperation(normalizedPath, path, method, scopes) {
        if (!this.isDangerousPath(normalizedPath) || !this.isSensitiveOperation(method, path)) {
            return undefined;
        }
        logger.warn('Dangerous operation attempted', { path, method, scopes });
        if (scopes.includes('Directory.ReadWrite.All')) {
            return undefined;
        }
        return {
            allowed: false,
            reason: 'Dangerous operation requires Directory.ReadWrite.All scope',
            requiredScopes: ['Directory.ReadWrite.All']
        };
    }
    /** `normalizedPath` must come from normalizePath(). Returns the matched entry, exact match first. */
    static getRequiredScopes(normalizedPath) {
        for (const [pattern, scopes] of Object.entries(this.REQUIRED_SCOPES_MAP)) {
            if (pattern.toLowerCase() === normalizedPath) {
                return { pattern, scopes };
            }
        }
        for (const [pattern, scopes] of Object.entries(this.REQUIRED_SCOPES_MAP)) {
            if (normalizedPath.startsWith(pattern.toLowerCase())) {
                return { pattern, scopes };
            }
        }
        return undefined;
    }
    static isSensitiveOperation(method, path) {
        return this.SENSITIVE_OPERATIONS.includes(method.toUpperCase());
    }
    /** `normalizedPath` must come from normalizePath(). */
    static isDangerousPath(normalizedPath) {
        return this.DANGEROUS_PATHS.some(dangerous => normalizedPath.includes(dangerous.toLowerCase()));
    }
    static isScopeSufficient(userScope, requiredScope) {
        // Directory permissions only imply other directory-family permissions, never Files.* / Sites.*
        const directoryFamily = this.DIRECTORY_FAMILIES.some(prefix => requiredScope.startsWith(prefix));
        if (!directoryFamily) {
            return false;
        }
        // Directory.ReadWrite.All covers most specific directory scopes
        if (userScope === 'Directory.ReadWrite.All' && !requiredScope.includes('RoleManagement')) {
            return true;
        }
        // Directory.Read.All covers most directory read scopes
        if (userScope === 'Directory.Read.All' && requiredScope.includes('Read') && !requiredScope.includes('Write')) {
            return true;
        }
        return false;
    }
}
// Security configuration validator
export class SecurityConfigValidator {
    static validateConfiguration() {
        const errors = [];
        // Check for production mode
        const isProduction = process.env.NODE_ENV === 'production';
        if (isProduction) {
            // In production, certain things should be configured
            if (process.env.ENABLE_LOGGING === 'true' && !process.env.LOG_DIR) {
                errors.push('LOG_DIR should be configured in production when logging is enabled');
            }
            if (!process.env.RATE_LIMIT_MAX) {
                errors.push('Rate limiting should be explicitly configured in production');
            }
            if (process.env.USE_INTERACTIVE === 'true') {
                errors.push('Interactive authentication should not be used in production');
            }
            if (!process.env.STRICT_PERMISSION_MODE || process.env.STRICT_PERMISSION_MODE !== 'true') {
                errors.push('STRICT_PERMISSION_MODE should be enabled in production for scope-based access control');
            }
            // Check for secure redirect URI
            const redirectUri = process.env.REDIRECT_URI;
            if (redirectUri && redirectUri.startsWith('http://') && !redirectUri.includes('localhost')) {
                errors.push('Redirect URI should use HTTPS in production');
            }
        }
        // Check for conflicting authentication modes
        const authModes = [
            process.env.USE_INTERACTIVE === 'true',
            process.env.USE_CLIENT_TOKEN === 'true',
            process.env.USE_CERTIFICATE === 'true',
            !!process.env.CLIENT_SECRET
        ];
        const enabledModes = authModes.filter(Boolean).length;
        if (enabledModes > 1) {
            errors.push('Multiple authentication modes are enabled. Only one should be active.');
        }
        if (enabledModes === 0) {
            errors.push('No authentication mode is configured.');
        }
        // Validate certificate configuration
        if (process.env.USE_CERTIFICATE === 'true') {
            if (!process.env.CERTIFICATE_PATH) {
                errors.push('CERTIFICATE_PATH is required when USE_CERTIFICATE is true');
            }
        }
        return {
            valid: errors.length === 0,
            errors
        };
    }
}
// Export rate limiter instance
export const rateLimiter = new RateLimiter();
// Helper function to get client identifier for rate limiting
export function getClientIdentifier(context) {
    // Use a combination of auth mode and tenant/client ID
    const tenantId = process.env.TENANT_ID || 'unknown';
    const clientId = process.env.CLIENT_ID || 'unknown';
    return `${tenantId}:${clientId}`;
}
// Startup security warnings
if (process.env.STRICT_PERMISSION_MODE !== 'true') {
    logger.warn('SECURITY: STRICT_PERMISSION_MODE is not enabled. Permission scope validation is bypassed for all operations. Set STRICT_PERMISSION_MODE=true in production.');
}
