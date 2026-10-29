import { logger } from "./logger.js";
import { emergencyControls } from "./emergency-controls.js";
import { rateLimiter, getClientIdentifier } from "./security.js";
export class PolicyViolation extends Error {
    code;
    constructor(code, message) {
        super(message);
        this.code = code;
        this.name = "PolicyViolation";
    }
}
const SITE_FILES_READ_OPERATIONS = new Set([
    "search", "list", "get_metadata", "get_content", "list_folders",
    "recent", "by_type", "large_files", "shared", "site_info",
]);
const LISTS_READ_OPERATIONS = new Set(["list_lists", "get_items"]);
/** Unknown operations are treated as writes so a new operation cannot slip past read-only mode. */
export function siteFilesVerb(operation) {
    return SITE_FILES_READ_OPERATIONS.has(operation) ? "read" : "write";
}
export function listsVerb(operation) {
    return LISTS_READ_OPERATIONS.has(operation) ? "read" : "write";
}
export function graphMethodVerb(method) {
    return method.toUpperCase() === "GET" ? "read" : "write";
}
export class PolicyGuard {
    deps;
    constructor(deps) {
        this.deps = deps;
    }
    async enforce(request) {
        const { tool, verb, resource } = request;
        const method = verb === "read" ? "GET" : "POST";
        // Emergency mode first, and without touching any credential, so a shutdown is honoured
        // even when authentication is missing or broken. Persisted state is loaded asynchronously,
        // so wait for it: a shutdown written by a previous run must apply to the very first call.
        await this.deps.emergency.ready();
        const emergencyBlock = this.deps.emergency.checkAccess(method, resource);
        if (emergencyBlock) {
            this.deny(tool, verb, resource, "emergency", emergencyBlock);
        }
        const clientId = getClientIdentifier({});
        if (!this.deps.rateLimiter.isAllowed(clientId)) {
            const remaining = this.deps.rateLimiter.getRemainingRequests(clientId);
            this.deny(tool, verb, resource, "rate_limit", `Rate limit exceeded. Please wait before making more requests. Remaining requests: ${remaining}`);
        }
    }
    deny(tool, verb, resource, code, message) {
        logger.audit("POLICY_BLOCK", {
            action: `${tool}:${verb}`,
            result: "FAILURE",
            targetResource: resource,
            metadata: { code },
        });
        throw new PolicyViolation(code, message);
    }
}
export const policyGuard = new PolicyGuard({ emergency: emergencyControls, rateLimiter });
