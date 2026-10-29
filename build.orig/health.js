const APP_ONLY_MODES = new Set(["client_credentials", "certificate"]);
export async function computeHealth(input) {
    const checks = {};
    const isAuthenticated = input.tokenStatus.hasCredential && !input.tokenStatus.isExpired;
    const initState = input.initialization?.state ?? "ready";
    checks.authentication = {
        status: isAuthenticated ? "healthy" : initState === "pending" ? "pending" : "unhealthy",
        mode: input.authMode ?? "not_initialized",
        initialization: initState,
        initializationError: input.initialization?.error,
        isAuthenticated,
        hasCredential: input.tokenStatus.hasCredential,
        isExpired: input.tokenStatus.isExpired,
        expiresOn: input.tokenStatus.expiresOn,
    };
    if (!isAuthenticated && initState === "pending") {
        checks.graphApi = { status: "pending", connected: null, reason: "authentication still initializing" };
    }
    else if (!isAuthenticated) {
        checks.graphApi = { status: "unhealthy", connected: false, reason: "not authenticated" };
    }
    else if (input.emergency.mode !== "normal") {
        // Status must stay local while resource access is restricted.
        checks.graphApi = { status: "skipped", connected: null, reason: `emergency mode: ${input.emergency.mode}` };
    }
    else if (APP_ONLY_MODES.has(input.authMode ?? "")) {
        checks.graphApi = { status: "untested", connected: null, reason: "app-only credential; no delegated probe available" };
    }
    else {
        try {
            await input.probeGraph();
            checks.graphApi = { status: "healthy", connected: true };
        }
        catch (error) {
            checks.graphApi = {
                status: "degraded",
                connected: false,
                reason: error?.statusCode ? `HTTP ${error.statusCode}` : "request failed",
            };
        }
    }
    checks.emergencyControls = {
        status: input.emergency.mode === "normal" ? "healthy" : "warning",
        mode: input.emergency.mode,
        isActive: input.emergency.isActive,
    };
    checks.rateLimit = {
        status: input.rateLimitRemaining > 10 ? "healthy" : "warning",
        remainingRequests: input.rateLimitRemaining,
    };
    checks.tokenRevocation = { status: "healthy", ...input.revocation };
    if (input.zeroTrust !== undefined) {
        checks.zeroTrust = { status: "healthy", ...input.zeroTrust };
    }
    const statuses = Object.values(checks).map(c => c.status);
    let status = "healthy";
    if (statuses.includes("unhealthy")) {
        status = "unhealthy";
    }
    else if (statuses.some(s => s === "degraded" || s === "warning" || s === "pending" || s === "skipped")) {
        status = "degraded";
    }
    return { status, timestamp: new Date().toISOString(), version: input.version, checks };
}
