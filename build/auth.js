import { ClientSecretCredential, ClientCertificateCredential } from "@azure/identity";
import jwt from "jsonwebtoken";
import { logger } from "./logger.js";
import { DefaultClientId, DefaultTenantId, DefaultRedirectUri } from "./constants.js";
import { EncryptedTokenCache } from "./tokenCache.js";
import { JwtValidator } from "./jwt-validator.js";
import { tokenRevocationManager } from "./token-revocation.js";
import { createPersistentLogin, isAuthenticationRequired } from "./persistent-login.js";
// Constants
const ONE_HOUR_IN_MS = 60 * 60 * 1000; // One hour in milliseconds
const GRAPH_RESOURCE = "https://graph.microsoft.com/";
const GRAPH_DEFAULT_SCOPE = "https://graph.microsoft.com/.default";
const NOT_SIGNED_IN_MESSAGE = "Not signed in. Run the 'login' tool to sign in with Microsoft, then retry.";
const TRANSIENT_ACQUISITION_PREFIX = "Token acquisition failed (transient)";
/**
 * Wraps any credential so the local revocation blocklist is applied to the exact token being
 * handed out, for whatever resource was requested. This covers every token acquisition:
 * Graph, Azure management and per-page re-acquisition. The Graph SDK's retry handler resends
 * a request without re-acquiring, so graph-client.ts adds a per-attempt check for that path.
 */
export class RevocationCheckedCredential {
    inner;
    isRevoked;
    onToken;
    isLoginRequired;
    constructor(inner, isRevoked = (t) => tokenRevocationManager.isRevoked(t), 
    /** Invoked with every token handed out, so status can track silent refreshes. */
    onToken, 
    /**
     * Whether the owner knows there is no session and login() must be run. The SDK raises
     * AuthenticationRequiredError for transient keychain and network failures as well, so the
     * login hint is given only when this says so; otherwise the underlying cause is surfaced.
     * Without an owner to ask, the error is taken at face value.
     */
    isLoginRequired = () => true) {
        this.inner = inner;
        this.isRevoked = isRevoked;
        this.onToken = onToken;
        this.isLoginRequired = isLoginRequired;
    }
    async getToken(scopes, options) {
        let token;
        try {
            token = await this.inner.getToken(scopes, options);
        }
        catch (error) {
            if (isAuthenticationRequired(error)) {
                if (this.isLoginRequired())
                    throw new Error(NOT_SIGNED_IN_MESSAGE);
                const cause = error instanceof Error ? error.message : String(error);
                throw new Error(`${TRANSIENT_ACQUISITION_PREFIX}: ${cause}. Retry the request; if this keeps happening, run the 'login' tool.`);
            }
            throw error;
        }
        if (token?.token && this.isRevoked(token.token)) {
            logger.audit("TOKEN_REVOKED_USE_BLOCKED", {
                action: "GET_TOKEN",
                result: "FAILURE",
                targetResource: Array.isArray(scopes) ? scopes.join(" ") : scopes,
            });
            throw new Error("Access denied: this token has been revoked locally. Obtain a new token.");
        }
        if (token && this.onToken) {
            await this.onToken(token);
        }
        return token;
    }
}
/**
 * Reads scopes from a token that is already trusted: one the SDK just received from Azure AD, or
 * a pasted token that ClientProvidedTokenCredential has validated. Never call this on an
 * unvalidated token; validation lives in JwtValidator and is bound to the configured tenant.
 */
async function parseJwtScopes(token) {
    try {
        const decoded = jwt.decode(token);
        if (!decoded || typeof decoded !== 'object') {
            logger.info("Failed to decode JWT token");
            return [];
        }
        // Extract scopes from the 'scp' claim (space-separated string)
        const scopesString = decoded.scp;
        if (typeof scopesString === 'string') {
            return scopesString.split(' ').filter(scope => scope.length > 0);
        }
        // Some tokens might have roles instead of scopes
        const roles = decoded.roles;
        if (Array.isArray(roles)) {
            return roles;
        }
        logger.info("No scopes found in JWT token");
        return [];
    }
    catch (error) {
        logger.error("Error parsing JWT token for scopes", error);
        return [];
    }
}
// Simple authentication provider that works with Azure Identity TokenCredential
export class TokenCredentialAuthProvider {
    credential;
    constructor(credential) {
        this.credential = credential;
    }
    async getAccessToken() {
        const token = await this.credential.getToken("https://graph.microsoft.com/.default");
        if (!token) {
            throw new Error("Failed to acquire access token");
        }
        return token.token;
    }
}
export class ClientProvidedTokenCredential {
    validator;
    accessToken;
    expiresOn;
    tokenValidated = false;
    /** The validator is bound to the tenant in use; there is no process-wide default. */
    constructor(validator, accessToken, expiresOn) {
        this.validator = validator;
        if (accessToken) {
            this.accessToken = accessToken;
            this.expiresOn = expiresOn || new Date(Date.now() + ONE_HOUR_IN_MS); // Default 1 hour
            // Note: We'll validate the token asynchronously in validateAndSetToken method
            // Constructor can't be async, so validation happens in AuthManager.initialize()
        }
        else {
            this.expiresOn = new Date(0); // Set to epoch to indicate no valid token
        }
    }
    // New method to validate and set token (called from AuthManager)
    async validateAndSetToken(accessToken, expiresOn) {
        try {
            // Validate the token cryptographically against the configured tenant and Graph audience
            const decoded = await this.validator.validateToken(accessToken);
            // Check if token has required Graph API scopes
            const scopes = decoded.scp ? decoded.scp.split(' ') : [];
            if (scopes.length === 0 && !decoded.roles) {
                logger.warn("Token has no scopes or roles");
            }
            // Token is valid, store it
            this.accessToken = accessToken;
            // The JWT's exp claim is authoritative. A caller may shorten the lifetime, never extend it.
            const jwtExpiry = new Date(decoded.exp * 1000);
            const callerExpiryIsUsable = expiresOn instanceof Date && !Number.isNaN(expiresOn.getTime());
            this.expiresOn = callerExpiryIsUsable && expiresOn < jwtExpiry ? expiresOn : jwtExpiry;
            this.tokenValidated = true;
            logger.info("Client-provided token validated successfully", {
                subject: decoded.sub,
                issuer: decoded.iss,
                scopes: scopes.length,
                expires: this.expiresOn
            });
        }
        catch (error) {
            logger.error("Client-provided token validation failed", error);
            throw new Error(`Invalid token: ${error instanceof Error ? error.message : 'Validation failed'}`);
        }
    }
    async getToken(scopes) {
        // A pasted token is minted for Microsoft Graph only. Never hand it to another resource.
        const requested = Array.isArray(scopes) ? scopes : [scopes];
        if (!requested.every(scope => scope.startsWith(GRAPH_RESOURCE))) {
            logger.error("Client-provided token is scoped to Microsoft Graph and cannot be used for the requested resource", { scopes: requested });
            return null;
        }
        if (!this.tokenValidated) {
            logger.error("Access token has not been validated");
            return null;
        }
        if (!this.accessToken || !this.expiresOn || this.expiresOn <= new Date()) {
            logger.error("Access token is not available or has expired");
            return null;
        }
        return {
            token: this.accessToken,
            expiresOnTimestamp: this.expiresOn.getTime()
        };
    }
    async updateToken(accessToken, expiresOn) {
        // Validate token before updating
        await this.validateAndSetToken(accessToken, expiresOn);
    }
    isExpired() {
        return !this.expiresOn || this.expiresOn <= new Date();
    }
    hasValidatedToken() {
        return this.tokenValidated && !!this.accessToken;
    }
    getExpirationTime() {
        return this.expiresOn || new Date(0);
    }
    // Getter for access token (for internal use by AuthManager)
    getAccessToken() {
        return this.accessToken;
    }
}
export var AuthMode;
(function (AuthMode) {
    AuthMode["ClientCredentials"] = "client_credentials";
    AuthMode["ClientProvidedToken"] = "client_provided_token";
    AuthMode["Interactive"] = "interactive";
    AuthMode["Certificate"] = "certificate";
})(AuthMode || (AuthMode = {}));
export class AuthManager {
    credential = null;
    config;
    tokenCache = null;
    cachedTokenUsed = false;
    pendingAuthInfo = null;
    lastKnownToken = null;
    persistentLogin = null;
    loginRequired = false;
    /** Client-token mode only: built from the configured tenant, null when the mode is misconfigured. */
    tokenValidator;
    isLoginRequired() {
        return this.loginRequired;
    }
    /**
     * Client-token mode fails closed: without both TENANT_ID and CLIENT_ID a pasted token cannot be
     * bound to a tenant, so no token is accepted at all. Called wherever a pasted token would be
     * validated, so the refusal comes with the same clear message at startup and on set-access-token.
     */
    requireTokenValidator() {
        if (!this.tokenValidator) {
            throw new Error("Client token mode requires both TENANT_ID and CLIENT_ID: pasted tokens are accepted only when issued " +
                "by the configured tenant for Microsoft Graph. Set both environment variables and restart the server.");
        }
        return this.tokenValidator;
    }
    /** Device-code prompt awaiting the user, if the interactive flow fell back to device code. */
    getPendingAuthInfo() {
        return this.pendingAuthInfo;
    }
    constructor(config) {
        this.config = config;
        this.tokenValidator = config.mode === AuthMode.ClientProvidedToken && config.tenantId && config.clientId
            ? new JwtValidator({ tenantId: config.tenantId })
            : null;
        // Interactive sessions use OS-protected SDK persistence, never the legacy bearer cache.
        // Manual-token persistence is opt-in and requires a separately provisioned secret.
        if (config.mode === AuthMode.ClientProvidedToken && process.env.ENABLE_TOKEN_CACHE === 'true' &&
            process.env.CACHE_ENCRYPTION_SECRET) {
            this.tokenCache = new EncryptedTokenCache();
        }
    }
    async initialize() {
        // An explicitly supplied token always wins. Only fall back to the cache when none was given.
        if (this.tokenCache && this.config.mode === AuthMode.ClientProvidedToken && !this.config.accessToken) {
            const cached = await this.tokenCache.loadToken();
            if (cached) {
                logger.info('Loading token from encrypted cache');
                this.config.accessToken = cached.token;
                this.config.expiresOn = cached.expiresOn;
                this.cachedTokenUsed = true;
            }
        }
        switch (this.config.mode) {
            case AuthMode.ClientCredentials:
                if (!this.config.tenantId || !this.config.clientId || !this.config.clientSecret) {
                    throw new Error("Client credentials mode requires tenantId, clientId, and clientSecret");
                }
                logger.info("Initializing Client Credentials authentication");
                this.credential = new ClientSecretCredential(this.config.tenantId, this.config.clientId, this.config.clientSecret);
                break;
            case AuthMode.ClientProvidedToken:
                logger.info("Initializing Client Provided Token authentication");
                const clientTokenCred = new ClientProvidedTokenCredential(this.requireTokenValidator(), this.config.accessToken, this.config.expiresOn);
                // Validate the token if one was provided
                if (this.config.accessToken) {
                    await clientTokenCred.validateAndSetToken(this.config.accessToken, this.config.expiresOn);
                }
                this.credential = clientTokenCred;
                break;
            case AuthMode.Certificate:
                if (!this.config.tenantId || !this.config.clientId || !this.config.certificatePath) {
                    throw new Error("Certificate mode requires tenantId, clientId, and certificatePath");
                }
                logger.info("Initializing Certificate authentication");
                this.credential = new ClientCertificateCredential(this.config.tenantId, this.config.clientId, {
                    certificatePath: this.config.certificatePath,
                    certificatePassword: this.config.certificatePassword
                });
                break;
            case AuthMode.Interactive:
                // Use defaults if not provided
                const tenantId = this.config.tenantId || DefaultTenantId;
                const clientId = this.config.clientId || DefaultClientId;
                logger.info(`Initializing Interactive authentication with tenant ID: ${tenantId}, client ID: ${clientId}`);
                // Restore the OS-protected session silently. Never open a browser here: Claude Desktop
                // starts several server processes, and only an explicit login() may prompt.
                this.persistentLogin = await createPersistentLogin({
                    tenantId: tenantId,
                    clientId: clientId,
                    redirectUri: this.config.redirectUri || DefaultRedirectUri,
                });
                this.credential = this.persistentLogin;
                try {
                    await this.persistentLogin.getToken(GRAPH_DEFAULT_SCOPE);
                    this.loginRequired = false;
                }
                catch (error) {
                    if (!isAuthenticationRequired(error))
                        throw error;
                    this.loginRequired = true;
                    logger.info("No saved Microsoft session; the 'login' tool must be run to sign in.");
                }
                break;
            default:
                throw new Error(`Unsupported authentication mode: ${this.config.mode}`);
        }
        // Test the credential
        await this.testCredential();
    }
    async updateAccessToken(accessToken, expiresOn) {
        if (this.config.mode !== AuthMode.ClientProvidedToken) {
            throw new Error("Token update only supported in client provided token mode");
        }
        // The server may start logged out (no token yet); create the credential holder on demand.
        const credential = this.credential instanceof ClientProvidedTokenCredential
            ? this.credential
            : new ClientProvidedTokenCredential(this.requireTokenValidator());
        // Validates cryptographically; throws and leaves state untouched on failure.
        await credential.updateToken(accessToken, expiresOn);
        this.credential = credential;
        this.cachedTokenUsed = false;
        if (this.tokenCache) {
            // Already validated above; do not run the validator a second time.
            const scopes = await parseJwtScopes(accessToken);
            await this.tokenCache.saveToken(accessToken, expiresOn || new Date(Date.now() + ONE_HOUR_IN_MS), scopes, {
                authMode: this.config.mode,
                tenantId: this.config.tenantId,
                clientId: this.config.clientId
            });
        }
    }
    async testCredential() {
        if (!this.credential) {
            throw new Error("Credential not initialized");
        }
        // Skip testing if ClientProvidedToken mode has no initial token
        if (this.config.mode === AuthMode.ClientProvidedToken && !this.config.accessToken) {
            logger.info("Skipping initial credential test as no token was provided at startup.");
            return;
        }
        // Interactive mode without a restorable session: nothing to test until login() runs.
        if (this.loginRequired) {
            return;
        }
        try {
            const token = await this.credential.getToken(GRAPH_DEFAULT_SCOPE);
            if (!token) {
                throw new Error("Failed to acquire token");
            }
            logger.info("Authentication successful");
            await this.recordKnownToken(token);
        }
        catch (error) {
            logger.error("Authentication test failed", error);
            throw error;
        }
        finally {
            // Whether sign-in succeeded or failed, the device-code prompt is no longer actionable.
            this.pendingAuthInfo = null;
        }
    }
    getGraphAuthProvider() {
        if (!this.credential) {
            throw new Error("Authentication not initialized");
        }
        return new TokenCredentialAuthProvider(this.wrapCredential(this.credential));
    }
    getAzureCredential() {
        if (!this.credential) {
            throw new Error("Authentication not initialized");
        }
        return this.wrapCredential(this.credential);
    }
    wrapCredential(credential) {
        // Interactive mode: once the user has signed out (or no session was restored), nothing is
        // handed out until login() runs, even if the SDK could still refresh silently. This is what
        // makes a logout whose keychain step failed still fail closed.
        const gated = {
            getToken: async (scopes, options) => {
                if (this.loginRequired)
                    throw new Error(NOT_SIGNED_IN_MESSAGE);
                return credential.getToken(scopes, options);
            },
        };
        return new RevocationCheckedCredential(gated, undefined, (token) => this.recordKnownToken(token), () => this.loginRequired);
    }
    getAuthMode() {
        return this.config.mode;
    }
    isClientCredentials() {
        return this.config.mode === AuthMode.ClientCredentials;
    }
    isClientProvidedToken() {
        return this.config.mode === AuthMode.ClientProvidedToken;
    }
    isInteractive() {
        return this.config.mode === AuthMode.Interactive;
    }
    /**
     * Updates the credential used by this AuthManager.
     * Use this instead of directly mutating the private credential field.
     */
    async updateCredential(newCredential) {
        // Verify the credential works before accepting it
        try {
            const testToken = await newCredential.getToken(GRAPH_DEFAULT_SCOPE);
            if (!testToken || !testToken.token) {
                throw new Error('Credential produced no token');
            }
            this.credential = newCredential;
            await this.recordKnownToken(testToken);
            logger.info('AuthManager credential updated and verified via updateCredential()');
        }
        catch (error) {
            logger.error('updateCredential: new credential failed verification', error);
            throw new Error(`Cannot update credential: verification failed. ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
    /**
     * Explicit interactive sign-in. This is the only code path that opens a browser or starts a
     * device-code flow. It is serialized across server processes by the persistence layer, so
     * several instances started together produce one prompt.
     */
    async login(options = {}) {
        if (this.config.mode !== AuthMode.Interactive) {
            throw new Error("The login tool only applies to interactive mode. Current mode: " + this.config.mode);
        }
        const tenantId = this.config.tenantId || DefaultTenantId;
        const clientId = this.config.clientId || DefaultClientId;
        if (options.useDeviceCode) {
            this.persistentLogin = await createPersistentLogin({
                tenantId,
                clientId,
                redirectUri: this.config.redirectUri || DefaultRedirectUri,
                deviceCode: (info) => {
                    // Cannot write to stdout in an MCP server; surface via get-auth-status instead.
                    this.pendingAuthInfo = {
                        verificationUri: info.verificationUri,
                        userCode: info.userCode,
                        message: info.message
                    };
                    logger.info("Device code sign-in pending; retrieve the code via get-auth-status");
                    return Promise.resolve();
                },
            });
            this.credential = this.persistentLogin;
        }
        if (!this.persistentLogin) {
            throw new Error("Authentication not initialized");
        }
        try {
            const token = await this.persistentLogin.login(GRAPH_DEFAULT_SCOPE);
            await this.recordKnownToken(token);
            this.loginRequired = false;
            logger.info("Interactive sign-in completed");
        }
        finally {
            this.pendingAuthInfo = null;
        }
        return this.getTokenStatus();
    }
    /**
     * Signs out of the interactive session: blocks the current token locally, optionally revokes
     * the user's refresh tokens at Microsoft through the supplied callback (a Graph call that
     * signs the user out of every application), then forgets the persisted session.
     */
    async logout(options = {}, revokeAtMicrosoft) {
        if (this.config.mode !== AuthMode.Interactive) {
            throw new Error("The logout tool only applies to interactive mode. Current mode: " + this.config.mode);
        }
        if (!this.persistentLogin) {
            throw new Error("Authentication not initialized");
        }
        const result = {
            localSessionCleared: [],
            tokenBlockedLocally: false,
            microsoftSessionsRevoked: options.revokeMicrosoftSessions ? false : 'not_requested',
        };
        // Grab the live token silently, if there is one, so it can be blocked and used for revocation.
        // This is best effort: a sign-out must complete even if the token cannot be fetched right now.
        let current = null;
        try {
            current = await this.persistentLogin.getToken(GRAPH_DEFAULT_SCOPE);
        }
        catch (error) {
            if (!isAuthenticationRequired(error)) {
                logger.warn("Could not fetch the current token during logout; clearing the session anyway", error);
            }
        }
        if (options.revokeMicrosoftSessions && current) {
            try {
                await revokeAtMicrosoft?.();
                result.microsoftSessionsRevoked = true;
            }
            catch (error) {
                const status = error?.statusCode ?? error?.status;
                result.microsoftSessionsRevoked = status === 403 || status === 401 ? 'not_permitted' : 'failed';
                result.microsoftError = error?.message;
                logger.warn("Revoking Microsoft sessions failed; continuing with local logout", error);
            }
        }
        try {
            if (current?.token) {
                await tokenRevocationManager.revokeToken(current.token, 'User logout', new Date(current.expiresOnTimestamp), 'logout-tool');
                result.tokenBlockedLocally = true;
            }
            result.localSessionCleared = await this.persistentLogin.logout();
        }
        finally {
            // Whatever the keychain did, this process is signed out: no status from the old token, no
            // device-code prompt to resume, and no token handed out until login() runs again.
            this.lastKnownToken = null;
            this.pendingAuthInfo = null;
            this.loginRequired = true;
        }
        logger.info("Interactive session signed out", result);
        return result;
    }
    /**
     * Builds a fully verified manager around an already-acquired credential without touching any
     * shared state. Callers swap the live manager only after this resolves, so a failed
     * re-authentication leaves the previous manager and client pair intact.
     */
    static async createWithCredential(config, credential) {
        const manager = new AuthManager(config);
        await manager.updateCredential(credential);
        return manager;
    }
    /** Remembers expiry and scopes of the last token seen, so status can answer without acquiring. */
    async recordKnownToken(token) {
        this.lastKnownToken = {
            expiresOn: new Date(token.expiresOnTimestamp),
            scopes: await parseJwtScopes(token.token),
        };
    }
    /**
     * Attempts to re-initialize credentials from cached token
     * Useful for recovering after server restart or when graphClient is null
     */
    async tryInitializeFromCache() {
        if (this.config.mode !== AuthMode.ClientProvidedToken || !this.tokenCache) {
            return false;
        }
        const cached = await this.tokenCache.loadToken();
        if (cached) {
            logger.info('Re-initializing authentication from cached token');
            this.config.accessToken = cached.token;
            this.config.expiresOn = cached.expiresOn;
            this.cachedTokenUsed = true;
            // Re-create the credential with the cached token and validate it
            const newCredential = new ClientProvidedTokenCredential(this.requireTokenValidator());
            try {
                await newCredential.validateAndSetToken(cached.token, cached.expiresOn);
                this.credential = newCredential;
            }
            catch (validationError) {
                logger.warn('Cached token failed validation, clearing cache', validationError);
                if (this.tokenCache) {
                    await this.tokenCache.clearCache();
                }
                return false;
            }
            return true;
        }
        return false;
    }
    async getTokenStatus() {
        if (this.credential instanceof ClientProvidedTokenCredential) {
            const hasCredential = this.credential.hasValidatedToken();
            const tokenStatus = {
                hasCredential,
                isExpired: !hasCredential || this.credential.isExpired(),
                expiresOn: hasCredential ? this.credential.getExpirationTime() : undefined,
                fromCache: this.cachedTokenUsed
            };
            // If we have a valid token, parse it to extract scopes
            if (!tokenStatus.isExpired) {
                const accessToken = this.credential.getAccessToken();
                if (accessToken) {
                    try {
                        // Don't validate again - it was already validated when set
                        const scopes = await parseJwtScopes(accessToken);
                        return {
                            ...tokenStatus,
                            scopes: scopes
                        };
                    }
                    catch (error) {
                        logger.error("Error parsing token scopes in getTokenStatus", error);
                        return tokenStatus;
                    }
                }
            }
            return tokenStatus;
        }
        else if (this.credential) {
            // SDK-managed credentials: answer from the last verified token. Never call getToken here,
            // because for an interactive credential that can start a second sign-in prompt.
            const known = this.lastKnownToken;
            const loginRequired = this.config.mode === AuthMode.Interactive ? this.loginRequired : undefined;
            if (!known || this.loginRequired) {
                return { hasCredential: true, isExpired: true, loginRequired };
            }
            return {
                hasCredential: true,
                isExpired: known.expiresOn <= new Date(),
                expiresOn: known.expiresOn,
                scopes: known.scopes,
                loginRequired
            };
        }
        return { hasCredential: false, isExpired: true };
    }
}
