# sharepoint-mcp 0.1.4-bblg.1 (Bush & Bush Law Group fork of @iimransarwar/sharepoint-mcp 0.1.3)

Upstream publishes only the compiled build (no repository field on npm), so this fork patches build/.


## BBLG firm setup: per-user sign-in only (Nov 18, 2026)

The firm's connector now signs in **as each user**, so it can only do what that person's own Microsoft 365 account is allowed to do. There is **no client secret** and no app-only (firm-wide) access. Firm-wide search is handled separately by the M365 Tenant Search connector.

Entra app "Grok Bot SharePoint MCP" (client ID `c69cdf91-8174-4afe-bf21-b3e827f65baa`):
- Client secrets: none (all deleted). Application permissions: none (removed with their admin consent).
- Delegated permissions (tenant-wide consent): User.Read, openid, profile, email, Files.ReadWrite.All, Sites.ReadWrite.All, Sites.Manage.All.
- Authentication: Mobile and desktop redirect URIs `http://localhost:3000` and `http://localhost`; **Allow public client flows = Yes** (needed for device-code sign-in on headless bot computers).

### Setup for any team member

1. Add the MCP server using [`bblg-mcp-config.json`](bblg-mcp-config.json) (stdio). Do **not** add `CLIENT_SECRET`, `USE_CLIENT_TOKEN` or `USE_CERTIFICATE`; if an old setup has a secret, remove it.
   Keep `"CONFIRM_WRITES": "false"` in `env`. Grok Bot advertises the MCP confirmation form but auto-declines it, so with `elicit` (default) or `token` every write comes back "Declined by the user". Grok Bot's own Auto-review still checks each call. You get full read and write access, limited to what your own account can do in SharePoint/OneDrive.
2. Run the **`login`** tool once and sign in with **your own** Microsoft account.
   - Browser available: a browser window opens.
   - Headless (e.g. a Grok Bot computer): call `login` with `useDeviceCode: true`, then read the code from `get-auth-status` (`pendingAuth`) and enter it at https://microsoft.com/devicelogin. Only enter codes your own bot gave you.
3. Check `get-auth-status`: `authMode` should be `interactive` and show your account.
4. The session is saved in OS-protected storage and refreshes silently (about 90 days of inactivity).

On a Grok Bot computer, if the sign-in does not persist across restarts, add this to `env`:
`"DBUS_SESSION_BUS_ADDRESS": "unix:path=/tmp/xdg-runtime-box/bus"` (Secret Service keychain).

If your connector was installed as a plugin with built-in env (e.g. the old secret-based plugin), uninstall it and add this config as a custom MCP server instead; editing the dashboard env does not override a plugin's built-in env. Restart the server process after changing env.

Troubleshooting:
- `invalid_client` on device-code sign-in: "Allow public client flows" is off on the app; ask IT.
- Every write "Declined by the user" or refused for elicitation: set `"CONFIRM_WRITES": "false"` in `env` and restart the connector.
- `Not signed in. Run the 'login' tool`: run `login` once as above.
- Access denied on a site/file: your own account lacks permission; ask the site owner.

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
