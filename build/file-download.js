import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { logger } from "./logger.js";
import { readPositiveInt } from "./constants.js";
/**
 * File download support (bblg fork, 0.1.4).
 *
 * Graph answers GET .../content with a 302 to a pre-authenticated SharePoint URL. The shared Graph
 * client refuses to follow it (OriginCheckMiddleware only allows graph.microsoft.com), so content is
 * fetched here instead: read the item's @microsoft.graph.downloadUrl through Graph, then stream it
 * with a byte cap. The URL itself never leaves this module: it is not logged and not returned.
 */
const DOWNLOAD_URL_KEYS = ["@microsoft.graph.downloadUrl", "@content.downloadUrl"];
const DEFAULT_ALLOWED_HOST_SUFFIXES = [".sharepoint.com", ".sharepoint.us", ".sharepoint-df.com", ".svc.ms", ".files.1drv.com", ".livefilestore.com"];
export function maxDownloadBytes() {
    return readPositiveInt("MAX_FILE_DOWNLOAD_SIZE", 104857600); // 100 MB, same default as file-parser
}
export function maxInlineBytes() {
    // Base64 returned in an MCP response grows by 4/3; keep the default modest.
    return readPositiveInt("MAX_INLINE_DOWNLOAD_SIZE", 10 * 1024 * 1024);
}
function allowedHostSuffixes() {
    const extra = (process.env.DOWNLOAD_ALLOWED_HOST_SUFFIXES || "").split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
    return [...DEFAULT_ALLOWED_HOST_SUFFIXES, ...extra];
}
export function assertDownloadUrlAllowed(url) {
    let parsed;
    try {
        parsed = new URL(url);
    }
    catch {
        throw new Error("Graph returned an invalid download URL");
    }
    const host = parsed.hostname.toLowerCase();
    if (parsed.protocol !== "https:" || parsed.username || parsed.password ||
        !allowedHostSuffixes().some(sfx => host.endsWith(sfx))) {
        throw new Error(`Refusing to download from unexpected host ${host}`);
    }
}
/** Removes pre-authenticated download URLs from any Graph payload, recursively. Mutates and returns. */
export function redactDownloadUrls(value, depth = 0) {
    if (!value || typeof value !== "object" || depth > 50)
        return value;
    if (Array.isArray(value)) {
        for (const v of value)
            redactDownloadUrls(v, depth + 1);
        return value;
    }
    for (const key of Object.keys(value)) {
        if (DOWNLOAD_URL_KEYS.includes(key)) {
            delete value[key];
        }
        else if (value[key] && typeof value[key] === "object") {
            redactDownloadUrls(value[key], depth + 1);
        }
    }
    return value;
}
/** Allowed local roots for saveToPath: cwd, home, tmp, plus DOWNLOAD_SAVE_DIRS (comma separated). */
function allowedSaveRoots() {
    const extra = (process.env.DOWNLOAD_SAVE_DIRS || "").split(",").map(s => s.trim()).filter(Boolean);
    return [process.cwd(), os.homedir(), os.tmpdir(), ...extra].map(p => path.resolve(p));
}
export function resolveSavePath(target) {
    if (!path.isAbsolute(target)) {
        throw new Error("saveToPath must be an absolute path");
    }
    const resolved = path.resolve(target);
    const roots = allowedSaveRoots();
    if (!roots.some(r => resolved === r || resolved.startsWith(r + path.sep))) {
        throw new Error(`saveToPath must be inside one of: ${roots.join(", ")} (set DOWNLOAD_SAVE_DIRS to add more)`);
    }
    return resolved;
}
/**
 * Converts a Graph /content path into the item path whose metadata carries the download URL:
 *   /drives/{d}/items/{i}/content          -> /drives/{d}/items/{i}
 *   /sites/{s}/drive/root:/a/b.pdf:/content -> /sites/{s}/drive/root:/a/b.pdf:
 * Returns null when the path is not a content path.
 */
export function contentPathToItemPath(p) {
    const m = /^(.*?)(:?)\/content\/?$/.exec(p);
    if (!m || !m[1])
        return null;
    return m[2] === ":" ? `${m[1]}:` : m[1];
}
const TEXT_MIME = /^(text\/|application\/(json|xml|javascript|x-www-form-urlencoded|csv|x-ndjson|yaml|x-yaml|sql)\b)|\+(json|xml)$/i;
export function isTextual(mimeType, name) {
    if (mimeType && TEXT_MIME.test(mimeType))
        return true;
    return /\.(txt|csv|tsv|json|md|xml|html?|ya?ml|log|ini|cfg|conf|sql|js|ts|py|ps1|sh|eml|ics|vcf)$/i.test(name || "");
}
async function streamToBuffer(body, limit) {
    const chunks = [];
    let received = 0;
    const reader = body.getReader ? body.getReader() : null;
    if (reader) {
        for (;;) {
            const { done, value } = await reader.read();
            if (done)
                break;
            received += value.length;
            if (received > limit) {
                await reader.cancel().catch(() => { });
                throw new Error(`Download aborted: content exceeded the ${limit} byte limit while streaming.`);
            }
            chunks.push(Buffer.from(value));
        }
    }
    else {
        for await (const chunk of body) {
            received += chunk.length;
            if (received > limit) {
                body.destroy?.();
                throw new Error(`Download aborted: content exceeded the ${limit} byte limit while streaming.`);
            }
            chunks.push(Buffer.from(chunk));
        }
    }
    return Buffer.concat(chunks);
}
/**
 * Downloads a drive item.
 * options: { itemPath, saveToPath?, overwrite?, encoding?: 'base64'|'text'|'auto', maxBytes?, fetchImpl? }
 * Returns a JSON-safe result (never contains the download URL).
 */
export async function downloadDriveItem(graphClient, options) {
    const { itemPath, saveToPath, overwrite = false, encoding = "base64" } = options;
    const doFetch = options.fetchImpl ?? globalThis.fetch;
    const hardCap = maxDownloadBytes();
    const inlineCap = Math.min(options.maxBytes ?? maxInlineBytes(), hardCap);
    // No $select: Graph omits the download URL from some $select'ed item responses, but always
    // includes it on a plain item GET.
    const meta = await graphClient.api(itemPath).get();
    if (meta.folder) {
        throw new Error(`'${meta.name}' is a folder, not a file`);
    }
    const downloadUrl = meta["@microsoft.graph.downloadUrl"];
    delete meta["@microsoft.graph.downloadUrl"];
    if (!downloadUrl) {
        throw new Error("Graph did not return a download URL for this item (it may be a OneNote/package item or you lack read access)");
    }
    const limit = saveToPath ? hardCap : inlineCap;
    if (meta.size && meta.size > limit) {
        throw new Error(`File is ${meta.size} bytes, over the ${saveToPath ? "download" : "inline"} limit of ${limit} bytes. ` +
            (saveToPath ? "Set MAX_FILE_DOWNLOAD_SIZE to raise it." : "Use saveToPath to write it to disk, or raise MAX_INLINE_DOWNLOAD_SIZE."));
    }
    assertDownloadUrlAllowed(downloadUrl);
    const response = await doFetch(downloadUrl, { method: "GET", redirect: "error" });
    if (!response.ok) {
        throw new Error(`Download failed with HTTP ${response.status}`);
    }
    const bytes = await streamToBuffer(response.body, limit);
    const sha256 = createHash("sha256").update(bytes).digest("hex");
    const mimeType = meta.file?.mimeType || response.headers?.get?.("content-type") || "application/octet-stream";
    const result = {
        id: meta.id,
        name: meta.name,
        mimeType,
        size: bytes.length,
        sha256,
        webUrl: meta.webUrl,
        lastModifiedDateTime: meta.lastModifiedDateTime,
        driveId: meta.parentReference?.driveId,
    };
    if (meta.file?.hashes?.quickXorHash)
        result.quickXorHash = meta.file.hashes.quickXorHash;
    if (options.raw) {
        return { ...result, bytes };
    }
    if (saveToPath) {
        const target = resolveSavePath(saveToPath);
        await fs.mkdir(path.dirname(target), { recursive: true });
        await fs.writeFile(target, bytes, { flag: overwrite ? "w" : "wx" });
        result.savedTo = target;
    }
    else {
        const asText = encoding === "text" || (encoding === "auto" && isTextual(mimeType, meta.name));
        if (asText) {
            result.encoding = "text";
            result.content = bytes.toString("utf8");
        }
        else {
            result.encoding = "base64";
            result.content = bytes.toString("base64");
        }
    }
    logger.info(`Downloaded drive item ${meta.id} (${bytes.length} bytes)${saveToPath ? " to disk" : " inline"}`);
    return result;
}
