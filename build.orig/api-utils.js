import { logger } from "./logger.js";
const DEFAULT_RETRY_CONFIG = {
    maxRetries: 3,
    initialDelay: 1000,
    maxDelay: 10000,
    backoffMultiplier: 2,
    retryableStatusCodes: [429, 503, 504, 502, 500],
    idempotent: true,
    notFoundAfterRetryIsSuccess: false,
};
/** Statuses on which Graph sends Retry-After. */
const RETRY_AFTER_STATUSES = [429, 503];
const TRANSIENT_NETWORK_CODES = ['ECONNRESET', 'ETIMEDOUT', 'ENOTFOUND'];
/** Reads one header from a Headers instance (as the Graph SDK error carries) or a plain record. */
function readHeader(headers, name) {
    if (!headers || typeof headers !== 'object')
        return undefined;
    if (typeof headers.get === 'function') {
        return headers.get(name) ?? undefined;
    }
    const record = headers;
    const key = Object.keys(record).find(k => k.toLowerCase() === name);
    const value = key ? record[key] : undefined;
    if (value === undefined || value === null)
        return undefined;
    return String(Array.isArray(value) ? value[0] : value);
}
/** Retry-After as milliseconds from now, in either its delta-seconds or HTTP-date form. */
export function parseRetryAfterMs(headers, now = Date.now()) {
    const raw = readHeader(headers, 'retry-after')?.trim();
    if (!raw)
        return undefined;
    if (/^\d+$/.test(raw))
        return Number(raw) * 1000;
    const at = Date.parse(raw);
    return Number.isNaN(at) ? undefined : Math.max(0, at - now);
}
/**
 * Execute a Graph API request with automatic retry logic
 */
export async function executeWithRetry(operation, config = {}) {
    const retryConfig = { ...DEFAULT_RETRY_CONFIG, ...config };
    let lastError;
    for (let attempt = 0; attempt <= retryConfig.maxRetries; attempt++) {
        try {
            return await operation();
        }
        catch (error) {
            lastError = error;
            const statusCode = error.statusCode || error.status || error.code;
            if (attempt > 0 && statusCode === 404 && retryConfig.notFoundAfterRetryIsSuccess) {
                // The previous attempt deleted it; only its response was lost.
                return undefined;
            }
            // Check if error is retryable
            const isRetryable = retryConfig.idempotent
                ? retryConfig.retryableStatusCodes.includes(statusCode) || TRANSIENT_NETWORK_CODES.includes(error.code)
                : statusCode === 429;
            if (!isRetryable || attempt === retryConfig.maxRetries) {
                throw error;
            }
            // Calculate delay with exponential backoff
            let delay = Math.min(retryConfig.initialDelay * Math.pow(retryConfig.backoffMultiplier, attempt), retryConfig.maxDelay);
            // Honour Retry-After, but never beyond maxDelay: a hostile or misconfigured server must
            // not be able to park this operation (and the tool call behind it) for hours.
            const retryAfter = RETRY_AFTER_STATUSES.includes(statusCode) ? parseRetryAfterMs(error.headers) : undefined;
            if (retryAfter !== undefined) {
                delay = Math.min(retryAfter, retryConfig.maxDelay);
            }
            logger.info(`Retrying operation after ${delay}ms (attempt ${attempt + 1}/${retryConfig.maxRetries})`);
            await new Promise(resolve => setTimeout(resolve, delay));
        }
    }
    throw lastError;
}
/**
 * Composes the throttler and the retry policy so that each attempt holds a throttler slot only
 * while its request is in flight. The backoff sleep happens outside the slot, so a few large
 * Retry-After responses cannot wedge every other tool behind them.
 */
export function createThrottledRetry(throttler) {
    return (operation, config) => executeWithRetry(() => throttler.execute(operation), config);
}
/**
 * Batch multiple Graph API requests
 */
export async function batchGraphRequests(graphClient, requests) {
    const results = new Map();
    // Graph API supports max 20 requests per batch
    const batchSize = 20;
    for (let i = 0; i < requests.length; i += batchSize) {
        const batch = requests.slice(i, i + batchSize);
        const batchRequest = {
            requests: batch.map(req => ({
                id: req.id,
                method: req.method,
                url: req.url,
                body: req.body,
                headers: {
                    'Content-Type': 'application/json'
                }
            }))
        };
        try {
            const response = await executeWithRetry(async () => graphClient.api('/$batch').post(batchRequest));
            // Process batch responses
            for (const resp of response.responses) {
                if (resp.status >= 200 && resp.status < 300) {
                    results.set(resp.id, resp.body);
                }
                else {
                    logger.warn(`Batch request ${resp.id} failed with status ${resp.status}`);
                    results.set(resp.id, { error: resp.body?.error || 'Request failed' });
                }
            }
        }
        catch (error) {
            logger.error('Batch request failed:', error);
            // Set error for all requests in this batch
            for (const req of batch) {
                results.set(req.id, { error: error.message });
            }
        }
    }
    return results;
}
/**
 * Simple in-memory cache with TTL
 */
export class SimpleCache {
    cache = new Map();
    defaultTTL;
    cleanupTimer;
    constructor(defaultTTLSeconds = 300) {
        this.defaultTTL = defaultTTLSeconds * 1000;
        // Clean up expired entries every minute. unref: a cache must never keep the process alive.
        this.cleanupTimer = setInterval(() => this.cleanup(), 60000);
        this.cleanupTimer.unref?.();
    }
    dispose() {
        clearInterval(this.cleanupTimer);
        this.cache.clear();
    }
    get(key) {
        const entry = this.cache.get(key);
        if (!entry)
            return undefined;
        if (Date.now() > entry.expiry) {
            this.cache.delete(key);
            return undefined;
        }
        return entry.value;
    }
    set(key, value, ttlMs) {
        const expiry = Date.now() + (ttlMs || this.defaultTTL);
        this.cache.set(key, { value, expiry });
    }
    delete(key) {
        this.cache.delete(key);
    }
    clear() {
        this.cache.clear();
    }
    cleanup() {
        const now = Date.now();
        for (const [key, entry] of this.cache.entries()) {
            if (now > entry.expiry) {
                this.cache.delete(key);
            }
        }
    }
}
/**
 * Create a timeout wrapper for promises
 */
export function withTimeout(promise, timeoutMs, timeoutError = 'Operation timed out') {
    let timer;
    const timeout = new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(timeoutError)), timeoutMs);
    });
    return Promise.race([promise, timeout]).finally(() => {
        if (timer)
            clearTimeout(timer); // the losing timer must not linger
    });
}
/**
 * Smart throttling for API requests
 */
export class RequestThrottler {
    requestQueue = [];
    activeRequests = 0;
    maxConcurrent;
    requestDelay;
    lastRequestTime = 0;
    constructor(maxConcurrent = 10, requestDelayMs = 100) {
        this.maxConcurrent = maxConcurrent;
        this.requestDelay = requestDelayMs;
    }
    async execute(operation) {
        // The slot is reserved synchronously inside acquireSlot, so a burst of concurrent callers
        // cannot all observe a free slot before any of them has claimed it.
        await this.acquireSlot();
        try {
            return await operation();
        }
        finally {
            this.activeRequests--;
            this.processQueue();
        }
    }
    acquireSlot() {
        if (this.activeRequests < this.maxConcurrent) {
            this.activeRequests++;
            return this.enforceDelay();
        }
        return new Promise(resolve => {
            this.requestQueue.push(() => {
                this.activeRequests++;
                this.enforceDelay().then(resolve);
            });
        });
    }
    /** Minimum spacing between request starts. */
    enforceDelay() {
        const now = Date.now();
        const wait = this.requestDelay - (now - this.lastRequestTime);
        if (wait <= 0) {
            this.lastRequestTime = now;
            return Promise.resolve();
        }
        this.lastRequestTime = now + wait;
        return new Promise(resolve => setTimeout(resolve, wait));
    }
    processQueue() {
        if (this.requestQueue.length > 0 && this.activeRequests < this.maxConcurrent) {
            const next = this.requestQueue.shift();
            next?.();
        }
    }
}
