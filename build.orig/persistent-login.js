import * as identity from '@azure/identity';
import { createHash, randomUUID } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
const LOCK_POLL_MS = 500;
const LOCK_HEARTBEAT_MS = 30 * 1000; // the holder touches its lock while a login is in flight
const LOCK_STALE_MS = 5 * 60 * 1000; // no heartbeat for 5 minutes AND owner not running => abandoned
const LOCK_WAIT_MS = 15 * 60 * 1000; // give up waiting on a live holder after 15 minutes
export function isAuthenticationRequired(error) {
    return error?.name === 'AuthenticationRequiredError';
}
/** Restore both the SDK token cache and its selected account. Neither contains a password. */
export async function createPersistentLogin(options) {
    const enabled = process.env.ENABLE_TOKEN_CACHE !== 'false';
    let record;
    let recordStore;
    let savedRecord = null;
    const name = 'sharepoint-mcp-' + createHash('sha256')
        .update(JSON.stringify([options.tenantId.toLowerCase(), options.clientId.toLowerCase()]))
        .digest('hex');
    if (enabled) {
        // Load native storage only when persistence is requested. No plaintext fallback.
        const [{ cachePersistencePlugin }, { PersistenceCreator, DataProtectionScope }] = await Promise.all([
            import('@azure/identity-cache-persistence'),
            import('@azure/msal-node-extensions'),
        ]);
        identity.useIdentityPlugin(cachePersistencePlugin);
        const storage = await PersistenceCreator.createPersistence({
            cachePath: join(homedir(), '.IdentityService', `${name}.account`),
            serviceName: 'sharepoint-mcp.authentication-record',
            accountName: name,
            dataProtectionScope: DataProtectionScope.CurrentUser,
            usePlaintextFileOnLinux: false,
        });
        savedRecord = await storage.load();
        if (savedRecord)
            record = validatedRecord(savedRecord, options);
        recordStore = storage;
    }
    function buildCredential() {
        const credentialOptions = {
            tenantId: options.tenantId,
            clientId: options.clientId,
            authenticationRecord: record,
            // getToken() must never prompt. Only authenticate(), called from login(), may.
            disableAutomaticAuthentication: true,
            tokenCachePersistenceOptions: {
                enabled,
                name,
                unsafeAllowUnencryptedStorage: false,
            },
        };
        return options.deviceCode
            ? new identity.DeviceCodeCredential({ ...credentialOptions, userPromptCallback: options.deviceCode })
            : new identity.InteractiveBrowserCredential({ ...credentialOptions, redirectUri: options.redirectUri });
    }
    let credential = buildCredential();
    /** Another process may have signed in while we waited; adopt its account so we go silent. */
    async function adoptLatestRecord() {
        if (!recordStore)
            return;
        const latest = await recordStore.load();
        if (latest && latest !== savedRecord) {
            record = validatedRecord(latest, options);
            savedRecord = latest;
            credential = buildCredential();
        }
    }
    const lockPath = join(options.lockDir ?? join(homedir(), '.IdentityService'), `${options.lockName ?? name}.login.lock`);
    /**
     * Only login() may call this: it holds the login lock, and the SDK's authenticate() always
     * permits interaction (its silent path maps keychain and network failures to
     * AuthenticationRequiredError), so it must never run from an ordinary tool call.
     */
    async function persistAccount(scopes, tokenOptions) {
        if (!recordStore)
            return;
        // With an account already cached this takes the SDK's silent path; it just yields the
        // public account record without decoding a Graph token or inspecting SDK internals.
        const account = await credential.authenticate(scopes, tokenOptions);
        if (!account)
            throw new Error('Sign-in succeeded but no account record was returned.');
        const serialized = identity.serializeAuthenticationRecord(account);
        if (serialized !== savedRecord) {
            await recordStore.save(serialized);
            savedRecord = serialized;
        }
    }
    // Serialize acquisition within this process so concurrent tools cannot start competing flows.
    let previous = Promise.resolve();
    function serialized(work) {
        const run = previous.then(work);
        previous = run.catch(() => undefined);
        return run;
    }
    return {
        getToken(scopes, tokenOptions) {
            // Strictly silent: restore from the cache or throw AuthenticationRequiredError. The account
            // record is persisted only by login(), never as a write-through from here.
            return serialized(() => credential.getToken(scopes, tokenOptions));
        },
        login(scopes, tokenOptions) {
            return serialized(async () => {
                const release = await acquireLock(lockPath, options.lockWaitMs ?? LOCK_WAIT_MS);
                try {
                    // Another process may have completed sign-in while we waited for the lock.
                    await adoptLatestRecord();
                    try {
                        const silent = await credential.getToken(scopes, tokenOptions);
                        if (silent) {
                            await persistAccount(scopes, tokenOptions);
                            return silent;
                        }
                    }
                    catch (error) {
                        if (!isAuthenticationRequired(error))
                            throw error;
                    }
                    const account = await credential.authenticate(scopes, tokenOptions); // the one prompt
                    if (!account)
                        throw new Error('Sign-in did not return an account.');
                    if (recordStore) {
                        const serialized = identity.serializeAuthenticationRecord(account);
                        if (serialized !== savedRecord) {
                            await recordStore.save(serialized);
                            savedRecord = serialized;
                        }
                    }
                    const token = await credential.getToken(scopes, tokenOptions); // now cached
                    if (!token)
                        throw new Error('Sign-in completed but no token was issued.');
                    return token;
                }
                finally {
                    await release();
                }
            });
        },
        logout() {
            return serialized(async () => {
                const release = await acquireLock(lockPath, options.lockWaitMs ?? LOCK_WAIT_MS);
                try {
                    const cleared = [];
                    if (enabled) {
                        // The refresh token goes first: once it is gone no process can silently resume this
                        // session, even if deleting the account record below fails. The SDK token cache is
                        // one OS-store item shared by every app that uses Azure Identity persistence, so only
                        // this app's entries are removed, under the SDK's own cross-process cache lock.
                        await pruneSharedTokenCache(name, options.clientId);
                        cleared.push('token-cache');
                    }
                    if (recordStore) {
                        await recordStore.delete();
                        cleared.push('account-record');
                    }
                    return cleared;
                }
                finally {
                    // Whatever the stores did, this process must not keep a restorable session in memory.
                    record = undefined;
                    savedRecord = null;
                    credential = buildCredential();
                    await release();
                }
            });
        },
    };
}
/**
 * Opens the Azure Identity plugin's token cache the same way the plugin does on each platform,
 * so logout can prune this app's entries from it. Mirrors @azure/identity-cache-persistence,
 * which does not export its factory. No plaintext fallback on any platform.
 */
async function openSharedTokenCache(name) {
    const ext = await import('@azure/msal-node-extensions');
    const service = 'Microsoft.Developer.IdentityService';
    const account = 'MSALCache';
    const localAppData = process.platform === 'win32'
        ? (process.env.LOCALAPPDATA ?? process.env.APPDATA?.replace(/(.Roaming)*$/, '\\Local') ?? homedir())
        : homedir();
    const cachePath = join(localAppData, '.IdentityService', name);
    switch (process.platform) {
        case 'darwin':
            return ext.KeychainPersistence.create(cachePath, service, account);
        case 'win32':
            return ext.FilePersistenceWithDataProtection.create(cachePath, ext.DataProtectionScope.CurrentUser);
        case 'linux':
            return ext.LibSecretPersistence.create(cachePath, service, account);
        default:
            throw new Error(`No secure token cache is available on platform ${process.platform}`);
    }
}
/** The part of msal-common's TokenCacheContext that PersistenceCachePlugin reads. */
class PruneContext {
    cache;
    hasChanged = true;
    constructor(cache) {
        this.cache = cache;
    }
    get cacheHasChanged() { return this.hasChanged; }
    get tokenCache() { return this.cache; }
}
/**
 * Removes this app's entries from the shared SDK token cache under the same cross-process lock the
 * SDK holds while it refreshes: PersistenceCachePlugin takes CrossPlatformLock on
 * `<cachePath>.lockfile` in beforeCacheAccess and releases it in afterCacheAccess, so a sibling
 * process mid-refresh cannot interleave with the prune. CrossPlatformLock itself is not exported by
 * @azure/msal-node-extensions (its exports map exposes only the package root), so the plugin's
 * ICachePlugin protocol is the supported way to take that lock.
 */
async function pruneSharedTokenCache(name, clientId) {
    const ext = await import('@azure/msal-node-extensions');
    const persistence = await openSharedTokenCache(name);
    // Same retry budget as @azure/identity-cache-persistence uses for its own plugin.
    const plugin = new ext.PersistenceCachePlugin(persistence, { retryNumber: 100, retryDelay: 50 });
    let loaded = null;
    let pruned = null;
    const context = new PruneContext({
        deserialize: (raw) => { loaded = raw; },
        serialize: () => pruned ?? loaded ?? '',
    });
    // Structurally what the plugin reads from msal-common's TokenCacheContext.
    const cacheContext = context;
    await plugin.beforeCacheAccess(cacheContext); // takes the lock and loads; keeps the lock while hasChanged
    try {
        pruned = loaded ? pruneMsalCache(loaded, clientId) : null;
        context.hasChanged = pruned !== null;
    }
    finally {
        await plugin.afterCacheAccess(cacheContext); // saves only when changed; always releases the lock
    }
}
/**
 * Removes every entry belonging to `clientId` from a serialized MSAL cache and returns the new
 * JSON, or null when nothing changed. Accounts are removed only when no other app still holds
 * a token for them. Unknown structure is left untouched rather than guessed at.
 */
export function pruneMsalCache(serialized, clientId) {
    let cache;
    try {
        cache = JSON.parse(serialized);
    }
    catch {
        return null;
    }
    if (!cache || typeof cache !== 'object')
        return null;
    const wanted = clientId.toLowerCase();
    let changed = false;
    const ownedAccounts = new Set();
    const foreignAccounts = new Set();
    for (const section of ['AccessToken', 'RefreshToken', 'IdToken', 'AppMetadata']) {
        const entries = cache[section];
        if (!entries || typeof entries !== 'object')
            continue;
        for (const [key, entry] of Object.entries(entries)) {
            const owner = String(entry?.client_id ?? '').toLowerCase();
            const account = entry?.home_account_id;
            if (owner === wanted) {
                delete entries[key];
                changed = true;
                if (account)
                    ownedAccounts.add(account);
            }
            else if (account) {
                foreignAccounts.add(account);
            }
        }
    }
    if (cache.Account && typeof cache.Account === 'object') {
        for (const [key, entry] of Object.entries(cache.Account)) {
            const account = entry?.home_account_id;
            if (account && ownedAccounts.has(account) && !foreignAccounts.has(account)) {
                delete cache.Account[key];
                changed = true;
            }
        }
    }
    return changed ? JSON.stringify(cache) : null;
}
function validatedRecord(serialized, options) {
    const record = identity.deserializeAuthenticationRecord(serialized);
    if (record.clientId.toLowerCase() !== options.clientId.toLowerCase()) {
        throw new Error('Stored sign-in belongs to a different application.');
    }
    // Single-tenant configurations must never restore another tenant's account.
    if (!['common', 'organizations', 'consumers'].includes(options.tenantId.toLowerCase()) &&
        record.tenantId.toLowerCase() !== options.tenantId.toLowerCase()) {
        throw new Error('Stored sign-in belongs to a different tenant.');
    }
    return record;
}
/**
 * Exclusive file lock shared by every server process on this machine for this tenant/client.
 * The file holds "<pid>:<token>". A lock is only considered abandoned when its heartbeat is old
 * AND its owning process is no longer running, so a slow but live login is never stolen. The
 * holder heartbeats by touching the file, and release() deletes the file only if it still holds
 * this process's own token.
 */
async function acquireLock(lockPath, waitMs) {
    await fs.mkdir(join(lockPath, '..'), { recursive: true });
    const token = `${process.pid}:${randomUUID()}`;
    const deadline = Date.now() + waitMs;
    for (;;) {
        try {
            const handle = await fs.open(lockPath, 'wx');
            await handle.writeFile(token);
            await handle.close();
            const heartbeat = setInterval(() => {
                const now = new Date();
                fs.utimes(lockPath, now, now).catch(() => undefined);
            }, LOCK_HEARTBEAT_MS);
            heartbeat.unref?.();
            return async () => {
                clearInterval(heartbeat);
                const current = await fs.readFile(lockPath, 'utf8').catch(() => null);
                if (current === token) {
                    await fs.unlink(lockPath).catch(() => undefined);
                }
            };
        }
        catch (error) {
            if (error?.code !== 'EEXIST')
                throw error;
            const judged = await judgeLock(lockPath);
            if (judged.abandoned) {
                // Compare-and-delete: between this judgement and the unlink, a faster waiter may already
                // have removed the stale file and written its own live lock. Only remove the exact
                // contents that were judged abandoned, never whatever happens to be there now.
                if (judged.contents !== null) {
                    const current = await fs.readFile(lockPath, 'utf8').catch(() => null);
                    if (current === judged.contents) {
                        await fs.unlink(lockPath).catch(() => undefined);
                    }
                }
                continue;
            }
            if (Date.now() > deadline) {
                throw new Error('Another sign-in has been in progress for too long. Complete or cancel it and retry.');
            }
            await new Promise(resolve => setTimeout(resolve, LOCK_POLL_MS));
        }
    }
}
async function judgeLock(lockPath) {
    const stat = await fs.stat(lockPath).catch(() => null);
    if (!stat)
        return { abandoned: true, contents: null }; // vanished between checks
    if (Date.now() - stat.mtimeMs <= LOCK_STALE_MS)
        return { abandoned: false };
    const contents = await fs.readFile(lockPath, 'utf8').catch(() => null);
    if (contents === null)
        return { abandoned: true, contents: null };
    const pid = parseInt(contents.split(':')[0], 10);
    if (!Number.isFinite(pid) || pid <= 0)
        return { abandoned: true, contents }; // unreadable owner: nobody can heartbeat it
    try {
        process.kill(pid, 0); // signal 0: existence check only
        return { abandoned: false }; // owner alive, just slow
    }
    catch (error) {
        return error?.code === 'ESRCH' // gone => abandoned; EPERM => alive
            ? { abandoned: true, contents }
            : { abandoned: false };
    }
}
