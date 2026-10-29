# sharepoint-mcp 0.1.4-bblg.1 (Bush & Bush Law Group fork of @iimransarwar/sharepoint-mcp 0.1.3)

Upstream publishes only the compiled build (no repository field on npm), so this fork patches build/.

## Fixes
1. Downloads work. Graph answers GET .../content with a 302 to a pre-authenticated SharePoint URL;
   upstream's Graph client (OriginCheckMiddleware) refuses any non-graph.microsoft.com hop, so
   - microsoft-graph GET .../content returned a hard-coded refusal, and
   - file-parser failed with "Refusing to send request to origin https://<tenant>.sharepoint.com".
   New build/file-download.js reads the item, takes its @microsoft.graph.downloadUrl internally, checks
   the host (https + *.sharepoint.com etc.), streams with a byte cap, and never returns or logs the URL.
2. New tool `download-file`: shareUrl | siteName | driveId | userId (+ itemId/fileId or filePath);
   returns base64/text inline (<= MAX_INLINE_DOWNLOAD_SIZE, default 10 MB) or writes to saveToPath
   (absolute path inside cwd, $HOME, tmp or DOWNLOAD_SAVE_DIRS; <= MAX_FILE_DOWNLOAD_SIZE, default 100 MB;
   no overwrite unless overwrite=true). Result includes name, mimeType, size, sha256, quickXorHash.
3. sharepoint-site-files get_content now returns the bytes (fileId or new filePath; saveToPath,
   downloadEncoding base64|text|auto) instead of handing out the raw downloadUrl.
4. microsoft-graph: GET .../content downloads (saveToPath/overwrite/downloadEncoding params), and every
   Graph response is scrubbed of @microsoft.graph.downloadUrl / @content.downloadUrl.
5. file-parser downloads through the same helper (fixes the origin error).

New env knobs: MAX_INLINE_DOWNLOAD_SIZE, DOWNLOAD_SAVE_DIRS, DOWNLOAD_ALLOWED_HOST_SUFFIXES.
Tests: test/unit.mjs (offline), test/live.mjs <pid-of-running-connector> (read-only, prints hashes only).
