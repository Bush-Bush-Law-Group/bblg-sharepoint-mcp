/**
 * Drive paths as the model types them (folderPath, destinationPath, filePath), made safe for the
 * `/sites/{id}/drive/root:/{path}:/children` family of Graph URLs.
 *
 * sanitizePath() validates the logical path (no traversal, nothing that could terminate the
 * `root:/…:` segment or start a query string). encodeDrivePath() then percent-encodes every path
 * segment, so whatever survives validation reaches Graph as path text and never as syntax.
 */
export const MAX_DRIVE_PATH_LENGTH = 1024;
/** Characters that must never appear in a logical drive path: URL delimiters and control characters. */
const FORBIDDEN_PATH_CHARS = /[?#:\\\x00-\x1f\x7f]/;
export function sanitizePath(inputPath) {
    if (inputPath.length > MAX_DRIVE_PATH_LENGTH) {
        throw new Error(`Invalid path: longer than ${MAX_DRIVE_PATH_LENGTH} characters.`);
    }
    // Decode URL-encoded characters first to catch %2e%2e, %3F etc.
    let decoded;
    try {
        decoded = decodeURIComponent(inputPath);
    }
    catch {
        decoded = inputPath; // Not valid percent-encoding: treat it as literal text (e.g. "100% done")
    }
    // Reject path traversal sequences (check both decoded and original)
    if (decoded.includes('..') || inputPath.includes('..')) {
        throw new Error(`Invalid path: path traversal sequences ('..') are not allowed.`);
    }
    // Reject anything that could end the root:/…: path segment or begin query options / a fragment.
    if (FORBIDDEN_PATH_CHARS.test(decoded) || FORBIDDEN_PATH_CHARS.test(inputPath)) {
        throw new Error(`Invalid path: the characters '?', '#', ':', '\\' and control characters are not allowed.`);
    }
    // Remove leading/trailing slashes
    return decoded.replace(/^\/+|\/+$/g, '');
}
/** Percent-encodes each '/'-separated segment of a sanitised drive path for use inside a Graph URL. */
export function encodeDrivePath(path) {
    return path.split('/').map(segment => encodeURIComponent(segment)).join('/');
}
/**
 * Encodes a value for `search(q='…')`: single quotes are doubled (OData string-literal escaping) so
 * the literal cannot be closed early, then the whole value is percent-encoded for the URL.
 */
export function encodeSearchTerm(term) {
    return encodeURIComponent(term.replace(/'/g, "''"));
}
