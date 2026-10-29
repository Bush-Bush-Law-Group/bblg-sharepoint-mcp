import { createHash, randomBytes } from "node:crypto";
import { logger } from "./logger.js";
/** Parses CONFIRM_WRITES. Unknown values are refused rather than mapped to a guess. */
export function parseConfirmMode(raw) {
    const value = (raw ?? "").trim().toLowerCase();
    if (value === "" || value === "true" || value === "elicit")
        return "elicit";
    if (value === "token")
        return "token";
    if (value === "false")
        return "false";
    throw new Error(`CONFIRM_WRITES must be one of "elicit" (default), "token" or "false"; got "${raw}"`);
}
export const CONFIRM_TOKEN_TTL_MS = 10 * 60 * 1000;
const MAX_OUTSTANDING_TOKENS = 1000;
/**
 * Tokens issued in token mode: random, single-use, expiring, and bound to the hash of the preview
 * they were issued for. Kept in memory; a restart invalidates every outstanding token.
 */
export class ConfirmationTokenStore {
    ttlMs;
    now;
    issued = new Map();
    constructor(ttlMs = CONFIRM_TOKEN_TTL_MS, now = Date.now) {
        this.ttlMs = ttlMs;
        this.now = now;
    }
    issue(preview) {
        this.sweep();
        const token = randomBytes(8).toString("hex");
        this.issued.set(token, { previewHash: previewToken(preview), expiresAt: this.now() + this.ttlMs });
        return token;
    }
    /** Forgets the token whatever the result, so a token is accepted at most once. */
    consume(token, preview) {
        const entry = this.issued.get(token);
        this.issued.delete(token);
        if (!entry)
            return "unknown";
        if (entry.expiresAt <= this.now())
            return "expired";
        return entry.previewHash === previewToken(preview) ? "ok" : "mismatch";
    }
    sweep() {
        const now = this.now();
        for (const [token, entry] of this.issued) {
            if (entry.expiresAt <= now)
                this.issued.delete(token);
        }
        // Map iteration is insertion-ordered, so the oldest outstanding tokens go first.
        while (this.issued.size >= MAX_OUTSTANDING_TOKENS) {
            const oldest = this.issued.keys().next().value;
            if (oldest === undefined)
                break;
            this.issued.delete(oldest);
        }
    }
}
/**
 * File/list operations that lose or displace data, plus every Graph write method: an arbitrary
 * POST/PUT/PATCH/DELETE through microsoft-graph can change or remove anything the token reaches.
 */
const DESTRUCTIVE = new Set(["delete", "update_content", "delete_item", "move", "post", "put", "patch"]);
/** Operations that lose or displace data get the extra typed-name check. Case-insensitive. */
export function isDestructive(operation) {
    return DESTRUCTIVE.has(operation.toLowerCase());
}
function canonical(value) {
    if (Array.isArray(value))
        return value.map(canonical);
    if (value && typeof value === "object") {
        return Object.keys(value).sort().reduce((acc, key) => {
            const v = value[key];
            if (v !== undefined)
                acc[key] = canonical(v);
            return acc;
        }, {});
    }
    return value;
}
/** Stable hash of the resolved preview; what a token is bound to and what the audit log records. */
export function previewToken(preview) {
    return createHash("sha256").update(JSON.stringify(canonical(preview))).digest("hex").slice(0, 16);
}
export function renderPreview(preview) {
    const lines = [];
    if (preview.site) {
        lines.push(`Site: ${preview.site.displayName ?? preview.site.id}${preview.site.webUrl ? ` <${preview.site.webUrl}>` : ""}`);
    }
    lines.push(`${preview.operations.length} write operation${preview.operations.length === 1 ? "" : "s"} via ${preview.tool}:`);
    for (const op of preview.operations) {
        const target = op.target
            ? ` -> ${op.target.kind ?? "item"} "${op.target.name}"${op.target.path ? ` in ${op.target.path}` : ""} (id ${op.target.id})`
            : "";
        const params = op.parameters && Object.keys(op.parameters).length > 0
            ? ` ${JSON.stringify(op.parameters)}`
            : "";
        lines.push(`  ${op.index}. ${op.operation}${target}${params}${isDestructive(op.operation) ? "  [destructive]" : ""}`);
    }
    return lines.join("\n");
}
export async function confirmWrite(preview, input, elicitor, options) {
    if (options.mode === "false") {
        return { approved: true, via: "disabled" };
    }
    const destructiveTargets = preview.operations
        .filter(op => isDestructive(op.operation) && op.target?.name)
        .map(op => op.target.name);
    if (elicitor?.supported()) {
        const properties = {
            proceed: { type: "boolean", title: `Proceed with ${preview.operations.length === 1 ? "this operation" : `all ${preview.operations.length} operations`}`, description: "Nothing is changed unless this is true." },
        };
        const required = ["proceed"];
        if (destructiveTargets.length > 0) {
            const example = destructiveTargets[0];
            properties.typedName = {
                type: "string",
                title: "Type the name of the item to be changed or deleted",
                description: destructiveTargets.length === 1
                    ? `Type exactly: ${example}`
                    : `Type the name of any one destructive target exactly, e.g. ${example}`,
            };
            required.push("typedName");
        }
        const response = await elicitor.ask(renderPreview(preview), { type: "object", properties, required });
        if (response.action === "decline")
            return deny(preview, "declined");
        if (response.action !== "accept")
            return deny(preview, "cancelled");
        if (response.content?.proceed !== true)
            return deny(preview, "declined");
        if (destructiveTargets.length > 0) {
            const typed = String(response.content?.typedName ?? "").trim();
            if (!destructiveTargets.some(name => name === typed))
                return deny(preview, "name_mismatch");
        }
        audit(preview, "APPROVED", "elicitation");
        return { approved: true, via: "elicitation" };
    }
    // The client cannot prompt the user. Only the operator's explicit opt-in allows the model to
    // confirm by echoing a token; by default the write is refused outright.
    if (options.mode === "elicit")
        return deny(preview, "elicitation_unavailable");
    const { tokens } = options;
    if (input.confirm !== true)
        return deny(preview, "confirmation_required", tokens.issue(preview));
    if (!input.confirmToken)
        return deny(preview, "token_missing", tokens.issue(preview));
    const result = tokens.consume(input.confirmToken, preview);
    if (result !== "ok") {
        const reason = result === "mismatch" ? "token_mismatch" : result === "expired" ? "token_expired" : "token_unknown";
        return deny(preview, reason, tokens.issue(preview));
    }
    audit(preview, "APPROVED", "token");
    return { approved: true, via: "token" };
}
function deny(preview, reason, token) {
    if (reason !== "confirmation_required")
        audit(preview, "REFUSED", reason);
    return { approved: false, reason, preview, token };
}
function audit(preview, result, detail) {
    logger.audit("WRITE_CONFIRMATION", {
        action: `${preview.tool}:${preview.operations.map(o => o.operation).join(",")}`,
        result: result === "APPROVED" ? "SUCCESS" : "FAILURE",
        targetResource: preview.site?.id ?? preview.tool,
        metadata: { detail, operations: preview.operations.length, preview: previewToken(preview) },
    });
}
/** Human-readable explanation for a refused or pending confirmation, returned as the tool result. */
export function explainOutcome(outcome) {
    const head = renderPreview(outcome.preview);
    const minutes = Math.round(CONFIRM_TOKEN_TTL_MS / 60000);
    const fresh = outcome.token
        ? ` To proceed, re-run the same call with confirm: true and confirmToken: "${outcome.token}" (single-use, valid for ${minutes} minutes, bound to these exact targets).`
        : "";
    switch (outcome.reason) {
        case "elicitation_unavailable":
            return `${head}\n\nNothing has been changed. This client does not support MCP elicitation, so the user cannot be asked to confirm this write, and the server will not let the model confirm on the user's behalf. Operator: connect with an elicitation-capable client, or set CONFIRM_WRITES=token to allow the two-step confirmToken flow, or CONFIRM_WRITES=false for unattended runs.`;
        case "confirmation_required":
            return `${head}\n\nNothing has been changed.${fresh} Any change to the targets invalidates the token.`;
        case "token_missing":
            return `${head}\n\nconfirm was true but confirmToken is missing. Nothing has been changed.${fresh}`;
        case "token_unknown":
            return `${head}\n\nThe confirmToken was not issued by this server, or it has already been used: tokens are single-use. Nothing has been changed.${fresh}`;
        case "token_expired":
            return `${head}\n\nThe confirmToken has expired (tokens are valid for ${minutes} minutes). Nothing has been changed.${fresh}`;
        case "token_mismatch":
            return `${head}\n\nThe confirmToken was issued for a different preview, so the targets differ from what was approved. Nothing has been changed.${fresh}`;
        case "declined":
            return `${head}\n\nDeclined by the user. Nothing has been changed.`;
        case "cancelled":
            return `${head}\n\nConfirmation was cancelled. Nothing has been changed.`;
        case "name_mismatch":
            return `${head}\n\nThe typed name did not match the destructive target. Nothing has been changed.`;
    }
}
