import { AuthenticationHandler, Client, HTTPMessageHandler, RedirectHandler, RedirectHandlerOptions, TelemetryHandler, } from "@microsoft/microsoft-graph-client";
import { logger } from "./logger.js";
import { tokenRevocationManager } from "./token-revocation.js";
/**
 * Re-checks the bearer token immediately before every outbound attempt. The chain built below has
 * no in-SDK retry (see createGraphClient), so each attempt is a fresh client call that runs the
 * AuthenticationHandler again; this middleware still guards a token that was revoked after it was
 * attached to the request, and any middleware that resends behind it.
 */
class RevocationCheckMiddleware {
    isRevoked;
    next;
    constructor(isRevoked) {
        this.isRevoked = isRevoked;
    }
    async execute(context) {
        const token = bearerTokenFrom(context.options?.headers);
        if (token && this.isRevoked(token)) {
            logger.audit("TOKEN_REVOKED_USE_BLOCKED", {
                action: "HTTP_ATTEMPT",
                result: "FAILURE",
                targetResource: typeof context.request === "string" ? context.request : context.request.url,
            });
            throw new Error("Access denied: this token has been revoked locally. Obtain a new token.");
        }
        if (!this.next)
            throw new Error("RevocationCheckMiddleware has no next handler");
        await this.next.execute(context);
    }
    setNext(middleware) {
        this.next = middleware;
    }
}
export const GRAPH_ORIGIN = "https://graph.microsoft.com";
export const AZURE_MANAGEMENT_ORIGIN = "https://management.azure.com";
/**
 * Refuses any request whose real origin is not exactly `expectedOrigin`. The Graph SDK's own host
 * check reads the hostname up to the first ':' so "https://graph.microsoft.com:443@evil.example/..."
 * passes it while the URL parser sends the request, bearer token included, to evil.example. This is
 * the last check before anything leaves the process and uses the same parser the runtime does.
 */
export function assertRequestOrigin(url, expectedOrigin) {
    let origin;
    try {
        origin = new URL(url).origin;
    }
    catch {
        throw new Error(`Refusing to send request: "${url}" is not a valid URL`);
    }
    if (origin !== expectedOrigin) {
        logger.audit("OUTBOUND_ORIGIN_BLOCKED", {
            action: "HTTP_ATTEMPT",
            result: "FAILURE",
            targetResource: url,
            metadata: { origin, expectedOrigin },
        });
        throw new Error(`Refusing to send request to origin ${origin}: only ${expectedOrigin} is allowed`);
    }
}
/** Sits immediately before the HTTP handler so retries and followed redirects are checked too. */
class OriginCheckMiddleware {
    expectedOrigin;
    next;
    constructor(expectedOrigin) {
        this.expectedOrigin = expectedOrigin;
    }
    async execute(context) {
        const url = typeof context.request === "string" ? context.request : context.request.url;
        assertRequestOrigin(url, this.expectedOrigin);
        if (!this.next)
            throw new Error("OriginCheckMiddleware has no next handler");
        await this.next.execute(context);
    }
    setNext(middleware) {
        this.next = middleware;
    }
}
function bearerTokenFrom(headers) {
    let value;
    if (!headers)
        return null;
    if (headers instanceof Headers) {
        value = headers.get("authorization");
    }
    else if (Array.isArray(headers)) {
        value = headers.find(([k]) => k.toLowerCase() === "authorization")?.[1];
    }
    else if (typeof headers === "object") {
        const record = headers;
        const key = Object.keys(record).find(k => k.toLowerCase() === "authorization");
        value = key ? record[key] : undefined;
    }
    if (!value)
        return null;
    const match = /^Bearer\s+(.+)$/i.exec(value);
    return match ? match[1] : null;
}
/**
 * The one way this server builds a Graph client, so every client carries the same chain.
 *
 * The SDK's RetryHandler is deliberately absent. It re-sends any buffered request answered
 * 429/503/504, including POST/PUT/PATCH/DELETE, so a create whose 504 arrived after the server had
 * committed the write was duplicated and a DELETE whose success response was lost was re-sent and
 * failed with 404; it also sleeps on Retry-After (up to 180 s per attempt) inside the request, i.e.
 * inside the throttler slot. Every retry is owned by executeWithRetry / throttledRetry in
 * api-utils.ts, which knows whether the operation is idempotent, caps the backoff at maxDelay and
 * sleeps outside the slot. A bare client call therefore sends exactly one attempt.
 */
export function createGraphClient(authProvider, options = {}) {
    const isRevoked = options.isRevoked ?? ((t) => tokenRevocationManager.isRevoked(t));
    const chain = [
        new AuthenticationHandler(authProvider),
        new RedirectHandler(new RedirectHandlerOptions()),
        new TelemetryHandler(),
        new RevocationCheckMiddleware(isRevoked),
        new OriginCheckMiddleware(GRAPH_ORIGIN),
        options.terminal ?? new HTTPMessageHandler(),
    ];
    for (let i = 0; i < chain.length - 1; i++) {
        chain[i].setNext?.(chain[i + 1]);
    }
    return Client.initWithMiddleware({ middleware: chain[0] });
}
