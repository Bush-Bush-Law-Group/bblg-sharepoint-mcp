// Shared constants for the SharePoint MCP Server
import { logger } from "./logger.js";
export const DefaultClientId = "";
export const DefaultTenantId = "common";
export const DefaultRedirectUri = "http://localhost:3000";
// Default Graph API version based on USE_GRAPH_BETA environment variable
export const getDefaultGraphApiVersion = () => {
    return process.env.USE_GRAPH_BETA !== 'false' ? "beta" : "v1.0";
};
/**
 * Reads an integer tuning knob from the environment. Anything that is not a plain decimal
 * integer within [min, max] (NaN, hex, fractions, negatives, zero where zero is meaningless,
 * unsafe magnitudes) falls back to the default with a warning, so a typo can never disable a
 * size limit (`x > NaN` is false), wedge the throttler (`0 < NaN` is false) or zero a window.
 */
export function readPositiveInt(name, defaultValue, bounds = {}) {
    const { min = 1, max = Number.MAX_SAFE_INTEGER } = bounds;
    const raw = process.env[name];
    if (raw === undefined || raw.trim() === '')
        return defaultValue;
    const trimmed = raw.trim();
    const value = /^\d+$/.test(trimmed) ? Number(trimmed) : NaN;
    if (!Number.isSafeInteger(value) || value < min || value > max) {
        logger.warn(`Ignoring invalid ${name}="${raw}": expected an integer between ${min} and ${max}; using default ${defaultValue}`);
        return defaultValue;
    }
    return value;
}
/** Upper bound on items accumulated by any fetchAll / fetch-every-page loop (F11). */
export const MAX_FETCH_ALL_ITEMS = readPositiveInt('MAX_FETCH_ALL_ITEMS', 5000, { min: 1, max: 100000 });
/** Upper bound on pages walked by any fetchAll / fetch-every-page loop (F11). */
export const MAX_FETCH_ALL_PAGES = readPositiveInt('MAX_FETCH_ALL_PAGES', 200, { min: 1, max: 10000 });
