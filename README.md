# SharePoint MCP Server

[![Version](https://img.shields.io/npm/v/@iimransarwar/sharepoint-mcp)](https://www.npmjs.com/package/@iimransarwar/sharepoint-mcp)

A Model Context Protocol (MCP) server that lets an AI assistant work with SharePoint, Microsoft Graph and Azure Resource Manager over stdio. It signs in with your Microsoft account or an app identity, and every write is resolved to an exact target and confirmed by you before it runs.

## Requirements

- Node.js 22.13 or newer
- An Entra ID app registration (see Authentication)
- For interactive sign-in on Linux: a working Secret Service (libsecret). macOS uses Keychain and Windows uses DPAPI.

## Install

```bash
npx -y @iimransarwar/sharepoint-mcp
```

or

```bash
npm install -g @iimransarwar/sharepoint-mcp
```

The persistence dependency builds a native module on install. If your npm has `ignore-scripts=true`, run `npm rebuild @azure/msal-node-extensions --ignore-scripts=false` afterwards, otherwise interactive mode reports a failed initialization.

## Authentication

One mode is chosen at startup:

| Mode | Selected by | Identity |
|---|---|---|
| Interactive | `USE_INTERACTIVE=true`, or default when no other mode applies | You, via browser or device code |
| Client token | `USE_CLIENT_TOKEN=true` | A Graph access token supplied by the client through `set-access-token` |
| Client credentials | `TENANT_ID`, `CLIENT_ID` and `CLIENT_SECRET` all set | The app |
| Certificate | `USE_CERTIFICATE=true` | The app |

Only one of `USE_INTERACTIVE`, `USE_CLIENT_TOKEN` and `USE_CERTIFICATE` may be set.

The MCP transport connects before authentication starts, so tools respond immediately. `get-auth-status` reports `initialization` as `pending`, `ready` or `failed` with the error. If initialization fails the server stays up, logged out.

### Interactive

Register an app in Entra ID: single tenant, redirect URI `http://localhost:3000` under **Mobile and desktop applications**, **Allow public client flows** set to Yes, delegated Graph permissions as needed (for example `User.Read`, `Sites.Read.All`, `Files.Read.All`; add `Sites.ReadWrite.All` and `Files.ReadWrite.All` only if you need writes). No client secret.

```json
{
  "mcpServers": {
    "sharepoint": {
      "command": "npx",
      "args": ["-y", "@iimransarwar/sharepoint-mcp"],
      "env": {
        "USE_INTERACTIVE": "true",
        "TENANT_ID": "<directory id>",
        "CLIENT_ID": "<application id>"
      }
    }
  }
}
```

`CLIENT_ID` is required. `TENANT_ID` defaults to `common`; set your tenant so a saved session from another tenant is never restored.

Flow:

1. Startup silently restores a saved session from OS-protected storage. It never opens a browser on its own. Without a saved session, `get-auth-status` reports `loginRequired: true` and resource tools return `Not signed in. Run the 'login' tool`.
2. Run **`login`** once. A browser opens for sign-in. Pass `useDeviceCode: true` for the device-code flow; while that call is pending, `get-auth-status` returns the code under `pendingAuth`.
3. The Azure Identity token cache and the selected account record are saved to Keychain, DPAPI or Secret Service. On restart the session is restored and tokens refresh silently for as long as the refresh token is valid (90 days of inactivity by default, subject to tenant policy). The browser reappears only when Microsoft invalidates the session, and only when you run `login` again.
4. **`logout`** blocks the current token locally, deletes this app's account record and removes this app's entries from the shared token cache. Other applications' sessions are untouched. `revokeMicrosoftSessions: true` also revokes your refresh tokens at Microsoft, which signs you out of every application; it needs a token permitted to revoke sessions.

Sign-in is serialized across processes with a lock, so several server instances started together produce one prompt. `ENABLE_TOKEN_CACHE=false` keeps the session in memory only; you sign in after every restart. There is no plaintext fallback: if secure storage is unavailable, initialization fails and the error is reported.

`add-graph-permission` requests additional delegated scopes with a fresh sign-in on the same saved account. The replacement credential is verified before it goes live.

### Client token

```json
"env": {
  "USE_CLIENT_TOKEN": "true",
  "TENANT_ID": "<directory id>",
  "CLIENT_ID": "<application id>"
}
```

Both IDs are required; without them initialization fails. The server starts logged out and accepts a token through `set-access-token`, which is confirmed like a write (see Write safety). The token is validated against Microsoft's signing keys: RS256, issuer and `tid` must match `TENANT_ID`, audience must be Microsoft Graph. A caller-supplied `expiresOn` can shorten the token's lifetime, never extend it. Pasted tokens are used for Graph only; Azure Resource Manager calls are refused. `ACCESS_TOKEN` may supply an initial token and takes precedence over any cached one.

Tokens are not persisted unless `ENABLE_TOKEN_CACHE=true` and `CACHE_ENCRYPTION_SECRET` are both set, in which case they are stored AES-256-GCM encrypted under `TOKEN_CACHE_DIR`.

### Client credentials

App registration with **Application** permissions and admin consent, plus a client secret.

```json
"env": {
  "TENANT_ID": "<directory id>",
  "CLIENT_ID": "<application id>",
  "CLIENT_SECRET": "<secret value>"
}
```

### Certificate

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
cat cert.pem key.pem > appcert.pem
openssl x509 -in cert.pem -outform DER -out cert.cer   # upload this to the app registration
```

```json
"env": {
  "TENANT_ID": "<directory id>",
  "CLIENT_ID": "<application id>",
  "USE_CERTIFICATE": "true",
  "CERTIFICATE_PATH": "/secure/path/appcert.pem",
  "CERTIFICATE_PASSWORD": "<only if the key is encrypted>"
}
```

App-only modes have no delegated `/me` probe, so `health-check` reports Graph connectivity as `untested`.

## Write safety

Every write on `sharepoint-site-files`, `sharepoint-lists` and `microsoft-graph`, and `set-access-token`, goes through the same sequence.

1. **Policy.** Emergency shutdown refuses everything except `get-auth-status` and `health-check`. Read-only mode refuses writes. Unknown operations count as writes. One rate limit applies to all tools.
2. **Exact target.** The site must be identified by its ID, its full URL or an exact display or internal name. Fuzzy first-result matching is used for reads only; an ambiguous name for a write is refused with the candidates listed.
3. **Preview.** The resolved site, item (name, path, kind, last modified) and parameters are shown. `dryRun: true` stops here without changing anything and is permitted in read-only mode.
4. **Confirmation**, governed by `CONFIRM_WRITES`:
   - `elicit` (default; `true` is an alias): the preview is shown to you as an MCP elicitation form. Destructive operations (`delete`, `move`, `update_content`, `delete_item`, and Graph `POST`/`PUT`/`PATCH`/`DELETE`) also require typing the target's name. A client that cannot show the form has the write refused with a message for the operator. The model is never given a way to approve its own request.
   - `token`: as above where the client can elicit. Otherwise the tool returns the preview with a random, single-use `confirmToken` valid for 10 minutes and bound to the previewed targets, and the call is re-run with `confirm: true` and that token. Opt in only if you accept that the model relays the confirmation.
   - `false`: no confirmation. For unattended runs.
5. **Execution** through a concurrency throttler. Non-idempotent requests are never retried; idempotent ones retry with capped backoff.

Every block, approval and refusal is written to the audit log.

## Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `TENANT_ID` | Directory (tenant) ID. Required for client-token, client-credentials and certificate modes | `common` (interactive only) |
| `CLIENT_ID` | Application (client) ID. Required in every mode | none |
| `CLIENT_SECRET` | Client secret; selects client-credentials mode with the two IDs | none |
| `USE_INTERACTIVE` | Select interactive mode | unset |
| `USE_CLIENT_TOKEN` | Select client-token mode | unset |
| `USE_CERTIFICATE` | Select certificate mode | unset |
| `CERTIFICATE_PATH`, `CERTIFICATE_PASSWORD` | PEM certificate and optional password | none |
| `REDIRECT_URI` | Interactive redirect URI | `http://localhost:3000` |
| `ACCESS_TOKEN` | Initial token for client-token mode | none |
| `ENABLE_TOKEN_CACHE` | Interactive: OS-protected session persistence. Client-token: encrypted file cache (also needs `CACHE_ENCRYPTION_SECRET`) | `true` |
| `CACHE_ENCRYPTION_SECRET` | Required to persist pasted tokens | none |
| `TOKEN_CACHE_DIR` | Directory for the client-token file cache | OS temp dir + `/.mcp-sharepoint-cache` |
| `CONFIRM_WRITES` | `elicit`, `token` or `false` | `elicit` |
| `EMERGENCY_SHUTDOWN` | Start in shutdown mode | `false` |
| `EMERGENCY_READONLY` | Start in read-only mode | `false` |
| `EMERGENCY_STATE_DIR` | Where emergency state persists | `LOG_DIR`, else `~/.sharepoint-mcp/state` |
| `TOKEN_REVOCATION_DIR` | Where the local token blocklist persists | `LOG_DIR`, else `~/.sharepoint-mcp/state` |
| `USE_GRAPH_BETA` | Default Graph endpoint version; `false` selects `v1.0` | `true` (beta) |
| `STRICT_PERMISSION_MODE` | Check token scopes against the requested path before calling Graph. Advisory: Graph remains the authority | `false` |
| `RATE_LIMIT_MAX`, `RATE_LIMIT_WINDOW_MS` | Requests per window, all tools combined | `100`, `60000` |
| `MAX_CONCURRENT_REQUESTS` | Simultaneous outbound requests (1 to 100) | `10` |
| `REQUEST_DELAY_MS` | Minimum spacing between request starts | `100` |
| `MAX_FETCH_ALL_ITEMS`, `MAX_FETCH_ALL_PAGES` | Caps for `fetchAll` and full site listings | `5000`, `200` |
| `MAX_FILE_DOWNLOAD_SIZE` | Bytes, enforced while streaming | `104857600` |
| `MAX_FILE_UPLOAD_SIZE` | Bytes, for `update_content` | `104857600` |
| `MAX_ZIP_EXTRACTED_SIZE` | Decompression budget for Word and PowerPoint | `52428800` |
| `MAX_SPREADSHEET_CELLS` | Cells serialised per sheet | `2000000` |
| `PARSE_TIMEOUT_MS` | Wall-clock limit per parse; parsing runs in a worker thread | `60000` |
| `ENABLE_LOGGING` | Write `mcp-server.log` | `false` |
| `LOG_LEVEL` | `ERROR`, `WARN`, `INFO`, `DEBUG` | `INFO` |
| `ENABLE_AUDIT_LOG` | Write `mcp-audit.log` (one JSON object per line) | `false` |
| `LOG_DIR` | Log directory, created 0700 with 0600 files | `~/.sharepoint-mcp/logs` |
| `ENABLE_ZERO_TRUST_MONITORING` | Report-only anomaly monitor | `true` |
| `ZERO_TRUST_ENFORCE` | Make the monitor block instead of report | `false` |
| `NODE_ENV` | `development` includes raw Graph error details in tool results | unset |

Numeric variables that are missing, non-numeric or out of range fall back to the default with a warning.

## Files written

| What | Where |
|---|---|
| Interactive session (tokens and account record) | OS secure store: macOS Keychain, Windows DPAPI-protected files, Linux Secret Service. Coordination files under `~/.IdentityService` (Windows: `%LOCALAPPDATA%\.IdentityService`) |
| Emergency state, token blocklist | `~/.sharepoint-mcp/state`, written via temp file and rename, symlinks refused |
| Logs | `~/.sharepoint-mcp/logs` when enabled |
| Client-token file cache | only with `ENABLE_TOKEN_CACHE=true` and `CACHE_ENCRYPTION_SECRET` |

Passwords are never stored. Log message text is stripped of control characters and passed through credential redaction; treat the log directory as sensitive regardless.

## Troubleshooting

- **`loginRequired: true`**: run `login`.
- **`initialization.state: failed`**: the error names the cause. Common ones: missing `CLIENT_ID`, missing `TENANT_ID` in client-token mode, secure storage locked or unavailable, native module not built.
- **Browser sign-in reports an invalid redirect URI**: add `http://localhost:3000` under Mobile and desktop applications and enable public client flows.
- **Write refused with "elicitation"**: your client cannot show confirmation forms. Use a client that can, or set `CONFIRM_WRITES=token`.
- **"No exact match for site"**: pass the site ID, full URL or exact display name for writes.
- **403 from Graph on a write**: the token lacks a write scope. Add `Sites.ReadWrite.All` or `Files.ReadWrite.All` to the app and run `login` again (or `add-graph-permission`).
- **Read-only mode error**: remove `EMERGENCY_READONLY` and restart.

## Upgrading from 0.0.x

- Interactive mode no longer signs in at startup; run `login` once. Sessions then persist in the OS secure store and the old `.mcp-sharepoint-cache` files are not used or migrated.
- Client-token mode requires `TENANT_ID` and `CLIENT_ID`, and `set-access-token` is confirmed like a write.
- Writes are confirmed before they run. On a client without elicitation, set `CONFIRM_WRITES=token` or `false`, otherwise writes are refused.
- Writes require an exactly identified site.
- `microsoft-graph` `path` must be relative; absolute URLs are refused.
- Listing results no longer include download URLs; use `get_content`.
- Node 22.13 or newer is required.

## Support

For issues, questions, or feature requests:
- Reach out to 1@1m.au

---

**Note**: This MCP (Model Context Protocol) server is an **independent project** and is **not officially affiliated with, endorsed by, or sponsored by Microsoft Corporation**. Microsoft Graph, SharePoint, Azure, and all related trademarks are the property of Microsoft Corporation.

## Terms of Use

By using this tool, you acknowledge and agree to the following:

### Your Responsibility
- **YOU** are solely responsible for how you use this tool
- **YOU** must ensure compliance with all applicable laws, regulations, and terms of service
- **YOU** must have proper authorization to access any systems, data, or resources
- **YOU** are responsible for any consequences resulting from your use of this tool

### No Liability
The developer(s) of this tool:
- Accept **NO responsibility** for any illegal, unauthorized, or improper use
- Are **NOT liable** for any damages, losses, or consequences arising from your use
- Provide this tool "AS IS" without any warranties, express or implied
- Make **NO guarantees** about the tool's functionality, reliability, or suitability for any purpose

### Prohibited Use
This tool must **NOT** be used for:
- Illegal activities of any kind
- Unauthorized access to systems or data
- Violating Microsoft's Terms of Service or any other service agreements
- Any activity that could harm individuals, organizations, or systems

### Data and Privacy
- The developer(s) do **NOT** collect, store, or have access to your data
- **YOU** are responsible for protecting any credentials, tokens, or sensitive information
- **YOU** must comply with all applicable data protection and privacy laws

## USE AT YOUR OWN RISK

By using this tool, you accept full responsibility for your actions and agree to indemnify and hold harmless the developer(s) from any and all claims, damages, or liabilities arising from your use.

**If you do not agree with these terms, DO NOT use this tool.**
