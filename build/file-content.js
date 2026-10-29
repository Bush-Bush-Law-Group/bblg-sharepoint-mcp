import { createHash } from "node:crypto";
import { logger } from "./logger.js";
/**
 * Replaces the bytes of an existing drive item. The item keeps its ID, name, sharing and
 * version history; SharePoint records a new version when the library has versioning enabled.
 *
 * Graph accepts a single PUT up to 4 MB. Above that an upload session is required, fed in
 * chunks whose sizes are multiples of 320 KiB (except the last).
 */
export const SIMPLE_UPLOAD_LIMIT = 4 * 1024 * 1024;
const CHUNK_SIZE = 327680 * 10; // 3.2 MiB, an aligned multiple of 320 KiB
export function decodeContent(content, encoding) {
    if (encoding === "text") {
        return Buffer.from(content, "utf8");
    }
    const normalized = content.replace(/\s+/g, "");
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized) || normalized.length % 4 !== 0) {
        throw new Error("content is not valid base64");
    }
    return Buffer.from(normalized, "base64");
}
/**
 * What a write preview shows for new file content: the decoded size and a digest of the decoded
 * bytes. The confirmation token is bound to the preview, so this ties the approval to the exact
 * bytes that will be written, not merely to a payload of the same length.
 */
export function describeContent(content, encoding) {
    const bytes = decodeContent(content, encoding);
    return { contentBytes: bytes.length, contentSha256: createHash("sha256").update(bytes).digest("hex") };
}
export async function replaceFileContent(graphClient, options) {
    const { siteId, fileId, content, maxBytes } = options;
    const doFetch = options.fetchImpl ?? fetch;
    if (content.length === 0) {
        throw new Error("Refusing to replace a file with empty content");
    }
    if (content.length > maxBytes) {
        throw new Error(`Content too large: ${content.length} bytes. Maximum allowed is ${maxBytes} bytes. ` +
            `Set MAX_FILE_UPLOAD_SIZE to raise the limit.`);
    }
    const itemPath = `/sites/${siteId}/drive/items/${fileId}`;
    if (content.length <= SIMPLE_UPLOAD_LIMIT) {
        const item = await graphClient.api(`${itemPath}/content`).put(content);
        return { item, bytes: content.length, method: "simple" };
    }
    const session = await graphClient.api(`${itemPath}/createUploadSession`).post({
        item: { "@microsoft.graph.conflictBehavior": "replace" },
    });
    if (!session?.uploadUrl) {
        throw new Error("Graph did not return an upload session URL");
    }
    let item = null;
    for (let offset = 0; offset < content.length; offset += CHUNK_SIZE) {
        const end = Math.min(offset + CHUNK_SIZE, content.length);
        const chunk = content.subarray(offset, end);
        const response = await doFetch(session.uploadUrl, {
            method: "PUT",
            headers: {
                "Content-Length": String(chunk.length),
                "Content-Range": `bytes ${offset}-${end - 1}/${content.length}`,
            },
            body: new Uint8Array(chunk),
        });
        if (!response.ok) {
            const detail = await response.text().catch(() => "");
            throw new Error(`Upload session chunk failed with HTTP ${response.status}${detail ? `: ${detail.slice(0, 200)}` : ""}`);
        }
        if (response.status === 200 || response.status === 201) {
            item = await response.json();
        }
        logger.debug("Uploaded chunk", { offset, end, total: content.length });
    }
    if (!item) {
        throw new Error("Upload session completed without returning the item");
    }
    return { item, bytes: content.length, method: "session" };
}
