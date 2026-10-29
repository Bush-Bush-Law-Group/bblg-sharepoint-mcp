#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ResponseType } from "@microsoft/microsoft-graph-client";
import fetch from 'isomorphic-fetch'; // Required polyfill for Graph client
import { logger } from "./logger.js";
import { AuthManager, AuthMode } from "./auth.js";
import { DefaultTenantId, DefaultRedirectUri, getDefaultGraphApiVersion, readPositiveInt, MAX_FETCH_ALL_ITEMS, MAX_FETCH_ALL_PAGES } from "./constants.js";
import { rateLimiter, getClientIdentifier, PermissionValidator, SecurityConfigValidator } from "./security.js";
import { microsoftGraphSchema, setAccessTokenSchema, getAuthStatusSchema, addGraphPermissionSchema, sharePointSiteFilesSchema, sharePointSiteDiscoverySchema, fileParserSchema, sharePointListsSchema, downloadFileSchema } from "./fix-schemas.js";
import { zeroTrustMonitor } from "./zero-trust-monitor.js";
import { tokenRevocationManager } from "./token-revocation.js";
import { emergencyControls } from "./emergency-controls.js";
import { policyGuard, graphMethodVerb, siteFilesVerb, listsVerb } from "./policy-guard.js";
import { createGraphClient, assertRequestOrigin, AZURE_MANAGEMENT_ORIGIN } from "./graph-client.js";
import { computeHealth } from "./health.js";
import { replaceFileContent, decodeContent, describeContent } from "./file-content.js";
import { downloadDriveItem, redactDownloadUrls, contentPathToItemPath } from "./file-download.js";
import { confirmWrite, explainOutcome, renderPreview, parseConfirmMode, ConfirmationTokenStore } from "./confirmation.js";
import { createRequire } from "module";
import crypto from 'crypto';
import { createEnhancedSharePointOperations } from "./sharepoint-enhancements.js";
import { sanitizePath, encodeDrivePath, encodeSearchTerm } from "./drive-path.js";
import { PaginationCache } from "./pagination-cache.js";
import { DRIVE_ITEM_LIST_SELECT, DRIVE_ITEM_CONTENT_SELECT, formatDriveItem, formatFileSize } from "./drive-item.js";
import { createThrottledRetry, batchGraphRequests, SimpleCache, withTimeout, RequestThrottler } from "./api-utils.js";
import { DocumentParser } from "./document-parser.js";
import { findSite } from "./site-utils.js";
// sanitizePath / encodeDrivePath / encodeSearchTerm live in ./drive-path.js (F10).
// Security: validate Graph API nextLink to prevent SSRF
function validateGraphNextLink(nextLink) {
    try {
        const url = new URL(nextLink);
        if (url.origin !== 'https://graph.microsoft.com') {
            throw new Error(`Blocked suspicious nextLink origin: ${url.origin}`);
        }
        return nextLink;
    }
    catch (error) {
        if (error instanceof Error && error.message.includes('Blocked'))
            throw error;
        throw new Error(`Invalid nextLink URL: ${nextLink}`);
    }
}
// Security: escape KQL special characters for search queries
function escapeKQL(input) {
    // Escape characters that have special meaning in KQL
    return input.replace(/["':\\*?<>|&]/g, (char) => `\\${char}`);
}
// Security: validate OData orderBy to prevent injection
function validateODataOrderBy(orderBy) {
    // Only allow field names with optional asc/desc
    const match = orderBy.match(/^[a-zA-Z_][a-zA-Z0-9_/]*(\s+(asc|desc))?$/i);
    if (!match) {
        throw new Error(`Invalid orderBy value: only field names with optional 'asc'/'desc' are allowed.`);
    }
    return orderBy;
}
// Security: validate OData expand to prevent injection
function validateODataExpand(expand) {
    // Only allow comma-separated field names with optional $select
    const parts = expand.split(',').map(p => p.trim());
    for (const part of parts) {
        if (!part.match(/^[a-zA-Z_][a-zA-Z0-9_]*(\(\$select=[a-zA-Z0-9_,\s*]+\))?$/)) {
            throw new Error(`Invalid expand value: only field names with optional $select are allowed.`);
        }
    }
    return expand;
}
// Security: basic OData filter validation
function validateODataFilter(filter) {
    // Reject dangerous patterns that could indicate injection
    const dangerousPatterns = [/--/, /;\s*\w/, /\/\*/, /\*\//, /xp_/, /exec\s*\(/i, /drop\s+/i];
    for (const pattern of dangerousPatterns) {
        if (pattern.test(filter)) {
            throw new Error(`Invalid filter: contains potentially dangerous pattern.`);
        }
    }
    return filter;
}
// Continuation state for site-discovery paging: bounded (LRU, 100 result sets) and expiring (15 min).
const paginationCache = new PaginationCache();
// Cache for site lookups (5 minute TTL)
const siteCache = new SimpleCache(300);
// Request throttler to prevent API overload
const requestThrottler = new RequestThrottler(readPositiveInt('MAX_CONCURRENT_REQUESTS', 10, { min: 1, max: 100 }), readPositiveInt('REQUEST_DELAY_MS', 100, { min: 0, max: 60_000 }));
/**
 * Every outbound Graph/ARM call goes through the retry policy, with each attempt taking a
 * throttler slot only while it is in flight (backoff sleeps happen outside the slot).
 */
const throttledRetry = createThrottledRetry(requestThrottler);
// Clean up expired continuation entries every 5 minutes
const paginationCleanup = setInterval(() => paginationCache.sweep(), 5 * 60 * 1000);
paginationCleanup.unref();
// Set up global fetch for the Microsoft Graph client
global.fetch = fetch;
// Create server instance
// Single source of truth for the version reported anywhere.
const SERVER_VERSION = createRequire(import.meta.url)("../package.json").version;
const server = new McpServer({
    name: "sharepoint-mcp",
    version: SERVER_VERSION,
});
logger.info("Starting SharePoint MCP Server (v0.2.0 - Token-Based Auth Support)");
// Initialize authentication and clients
let authManager = null;
let graphClient = null;
// One EnhancedSharePointOperations (search, paginator, cache and its timer) per Graph client,
// rebuilt only when the client is replaced, instead of one per search/list call.
let enhancedOps = null;
function getEnhancedOps(client) {
    if (enhancedOps && enhancedOps.client === client)
        return enhancedOps.ops;
    enhancedOps?.ops.dispose();
    enhancedOps = { client, ops: createEnhancedSharePointOperations(client) };
    return enhancedOps.ops;
}
// Write confirmation policy. CONFIRM_WRITES=elicit (default) needs an elicitation-capable client;
// 'token' opts into the two-step confirmToken fallback; 'false' disables confirmation for
// unattended runs. An unknown value throws here: a misconfigured gate must not pick a mode.
const confirmOptions = { mode: parseConfirmMode(process.env.CONFIRM_WRITES), tokens: new ConfirmationTokenStore() };
if (confirmOptions.mode === 'false') {
    logger.warn('CONFIRM_WRITES=false: write operations will run without user confirmation');
}
else if (confirmOptions.mode === 'token') {
    logger.warn('CONFIRM_WRITES=token: when the client cannot prompt the user, the model that requested a write may confirm it by echoing the preview token');
}
// Adapter over the MCP elicitation capability; null-safe when the client lacks it.
const elicitor = {
    supported: () => !!server.server.getClientCapabilities()?.elicitation,
    ask: (message, requestedSchema) => server.server.elicitInput({ message, requestedSchema: requestedSchema }),
};
/** Resolves a drive item into the compact shape shown in previews. */
async function resolveFileTarget(siteId, fileId) {
    const item = await throttledRetry(() => graphClient.api(`/sites/${siteId}/drive/items/${fileId}`).select('id,name,webUrl,size,folder,file,parentReference,lastModifiedDateTime').get());
    return {
        id: item.id, name: item.name, size: item.size,
        kind: item.folder ? 'folder' : 'file',
        path: item.parentReference?.path?.replace('/drive/root:', '') || '/',
        lastModified: item.lastModifiedDateTime,
    };
}
function compact(obj) {
    return Object.fromEntries(Object.entries(obj).filter(([, v]) => v !== undefined && v !== null && v !== ''));
}
// Startup authentication progress, readable via get-auth-status and health-check while an
// interactive sign-in is still pending.
let authInitialization = { state: 'pending' };
// Check USE_GRAPH_BETA environment variable
const useGraphBeta = process.env.USE_GRAPH_BETA !== 'false'; // Default to true unless explicitly set to 'false'
const defaultGraphApiVersion = getDefaultGraphApiVersion();
logger.info(`Graph API default version: ${defaultGraphApiVersion} (USE_GRAPH_BETA=${process.env.USE_GRAPH_BETA || 'undefined'})`);
// Helper function to add security headers to responses
function addSecurityHeaders(response) {
    // Add security headers (non-breaking, just metadata)
    if (!response.headers) {
        response.headers = {};
    }
    response.headers['X-Content-Type-Options'] = 'nosniff';
    response.headers['X-Frame-Options'] = 'DENY';
    response.headers['X-Request-ID'] = crypto.randomUUID();
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate';
    if (process.env.NODE_ENV === 'production') {
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
    }
    return response;
}
server.tool("microsoft-graph", "A versatile tool to interact with Microsoft APIs including Microsoft Graph (Entra) and Azure Resource Management. IMPORTANT: For Graph API GET requests using advanced query parameters ($filter, $count, $search, $orderby), you are ADVISED to set 'consistencyLevel: \"eventual\"'.", microsoftGraphSchema, async (params) => {
    const { apiType, path, method, apiVersion, subscriptionId, queryParams, body, graphApiVersion, fetchAll, consistencyLevel, confirm, confirmToken, saveToPath, overwrite, downloadEncoding } = params;
    // Local policy first, before any authentication check, so a shutdown is honoured
    // even when the credential is missing or broken.
    await policyGuard.enforce({ tool: 'microsoft-graph', verb: graphMethodVerb(method), resource: path });
    if (graphMethodVerb(method) === 'write') {
        const preview = {
            tool: 'microsoft-graph',
            operations: [{ index: 1, operation: method.toUpperCase(), target: { id: path, name: path, kind: apiType === 'azure' ? 'azure-resource' : 'graph-resource' },
                    parameters: compact({ apiType, body, queryParams, apiVersion, subscriptionId }) }],
        };
        const outcome = await confirmWrite(preview, { confirm, confirmToken }, elicitor, confirmOptions);
        if (!outcome.approved) {
            return { content: [{ type: "text", text: explainOutcome(outcome) }] };
        }
    }
    // Check and auto-initialize Graph client if needed
    if (!graphClient && authManager) {
        // Try to initialize from cached token if available
        if (authManager.getAuthMode() === AuthMode.ClientProvidedToken) {
            const reinitializedFromCache = await authManager.tryInitializeFromCache();
            if (reinitializedFromCache) {
                // Re-initialize graph client with cached token
                const authProvider = authManager.getGraphAuthProvider();
                graphClient = createGraphClient(authProvider);
                logger.info("Graph client auto-initialized from cached token");
            }
        }
        if (!graphClient) {
            if (authManager?.getAuthMode() === AuthMode.ClientProvidedToken) {
                throw new Error("Authentication not initialized. Please use the 'set-access-token' tool first to provide an access token.");
            }
            else {
                throw new Error("Graph client not initialized. Check authentication configuration.");
            }
        }
    }
    else if (!graphClient) {
        throw new Error("Graph client not initialized. Authentication system is not ready.");
    }
    // Zero Trust monitoring (Level 0.5 - Report Only Mode)
    // This is NON-BLOCKING and will not affect the request flow
    if (process.env.ENABLE_ZERO_TRUST_MONITORING !== 'false') {
        try {
            // Collect context asynchronously (fire and forget)
            const contextPromise = zeroTrustMonitor.collectContext({
                path,
                method,
                headers: {}, // Headers not available in params
                user: await authManager?.getTokenStatus()
            });
            // Calculate trust score in background (non-blocking)
            contextPromise.then(async (context) => {
                await zeroTrustMonitor.calculateTrustScore(context);
            }).catch(error => {
                // Log but don't fail the request
                logger.debug('Zero Trust monitoring error (non-blocking)', error);
            });
        }
        catch (error) {
            // Never block requests due to monitoring errors
            logger.debug('Zero Trust context collection failed (non-blocking)', error);
        }
    }
    // Permission validation for Graph API
    if (apiType === 'graph' && authManager) {
        const tokenStatus = await authManager.getTokenStatus();
        const scopes = tokenStatus.scopes || [];
        const permissionCheck = PermissionValidator.validateScopes(path, method, scopes);
        if (!permissionCheck.allowed) {
            logger.warn('Permission denied for operation', {
                path,
                method,
                reason: permissionCheck.reason,
                requiredScopes: permissionCheck.requiredScopes
            });
            throw new Error(`Permission denied: ${permissionCheck.reason}. Required scopes: ${permissionCheck.requiredScopes?.join(', ')}`);
        }
    }
    // Override graphApiVersion if USE_GRAPH_BETA is explicitly set to false
    const effectiveGraphApiVersion = !useGraphBeta ? "v1.0" : graphApiVersion;
    logger.info(`Executing microsoft-graph tool with params: apiType=${apiType}, path=${path}, method=${method}, graphApiVersion=${effectiveGraphApiVersion}, fetchAll=${fetchAll}, consistencyLevel=${consistencyLevel}`);
    let determinedUrl;
    try {
        let responseData;
        // --- Microsoft Graph Logic ---
        if (apiType === 'graph') {
            if (!graphClient) {
                throw new Error("Graph client not initialized");
            }
            determinedUrl = `https://graph.microsoft.com/${effectiveGraphApiVersion}`; // For error reporting
            // Construct the request using the Graph SDK client
            let request = graphClient.api(path).version(effectiveGraphApiVersion || defaultGraphApiVersion);
            // Add query parameters if provided and not empty
            if (queryParams && Object.keys(queryParams).length > 0) {
                // Filter out empty values and invalid search patterns
                const filteredParams = {};
                for (const [key, value] of Object.entries(queryParams)) {
                    // Skip empty values
                    if (value === '' || value === null || value === undefined) {
                        continue;
                    }
                    // Special handling for search parameter - skip invalid patterns
                    if (key === 'search' && (value === '*' || value === '')) {
                        logger.info(`Skipping invalid search parameter: '${value}'`);
                        continue;
                    }
                    filteredParams[key] = String(value);
                }
                // Only add query params if we have valid ones after filtering
                if (Object.keys(filteredParams).length > 0) {
                    request = request.query(filteredParams);
                }
            }
            // Add ConsistencyLevel header if provided
            if (consistencyLevel) {
                request = request.header('ConsistencyLevel', consistencyLevel);
                logger.info(`Added ConsistencyLevel header: ${consistencyLevel}`);
            }
            // Handle different methods
            switch (method.toLowerCase()) {
                case 'get':
                    // Check if this is a file content request (ends with /content)
                    if (contentPathToItemPath(path)) {
                        // bblg fork 0.1.4: download the bytes instead of refusing. Graph's /content
                        // answers with a redirect off graph.microsoft.com, which the origin-checked
                        // client will not follow, so fetch via the item's download URL with a byte cap.
                        logger.info(`File content download requested for path: ${path}`);
                        responseData = await throttledRetry(() => downloadDriveItem(graphClient, {
                            itemPath: contentPathToItemPath(path),
                            saveToPath, overwrite, encoding: downloadEncoding ?? 'base64'
                        }));
                        logger.audit('GRAPH_FILE_DOWNLOAD', { action: 'DOWNLOAD', targetResource: path, result: 'SUCCESS', metadata: { bytes: responseData.size, toDisk: !!saveToPath } });
                    }
                    else if (fetchAll) {
                        logger.info(`Fetching all pages for Graph path: ${path}`);
                        try {
                            const allItems = [];
                            // Fetch the first page to get context
                            const firstPageResponse = await request.get();
                            const odataContext = firstPageResponse['@odata.context'];
                            // Check if there's data to paginate
                            if (!firstPageResponse.value || firstPageResponse.value.length === 0) {
                                // No data, return empty result
                                responseData = {
                                    '@odata.context': odataContext,
                                    value: []
                                };
                                logger.info('No items found to paginate');
                            }
                            else {
                                // Walk @odata.nextLink ourselves: every link is origin-checked, and the walk stops
                                // at MAX_FETCH_ALL_ITEMS / MAX_FETCH_ALL_PAGES instead of growing without bound.
                                let page = firstPageResponse;
                                let pageCount = 1;
                                allItems.push(...page.value);
                                while (page['@odata.nextLink'] && allItems.length < MAX_FETCH_ALL_ITEMS && pageCount < MAX_FETCH_ALL_PAGES) {
                                    page = await graphClient.api(validateGraphNextLink(page['@odata.nextLink'])).get();
                                    pageCount++;
                                    allItems.push(...(page.value ?? []));
                                }
                                const truncated = allItems.length > MAX_FETCH_ALL_ITEMS || !!page['@odata.nextLink'];
                                if (allItems.length > MAX_FETCH_ALL_ITEMS)
                                    allItems.length = MAX_FETCH_ALL_ITEMS;
                                // Construct final response
                                responseData = {
                                    '@odata.context': odataContext,
                                    value: allItems,
                                    ...(truncated && {
                                        truncated: true,
                                        note: `Stopped after ${allItems.length} items across ${pageCount} pages (server caps: MAX_FETCH_ALL_ITEMS=${MAX_FETCH_ALL_ITEMS}, MAX_FETCH_ALL_PAGES=${MAX_FETCH_ALL_PAGES}). Narrow the query with $filter or $select, or page manually with fetchAll: false.`
                                    })
                                };
                                logger.info(`Finished fetching Graph pages. Total items: ${allItems.length}, pages: ${pageCount}, truncated: ${truncated}`);
                            }
                        }
                        catch (iteratorError) {
                            logger.error('Graph pagination error:', {
                                message: iteratorError.message || 'Unknown pagination error',
                                statusCode: iteratorError.statusCode,
                                code: iteratorError.code,
                                requestId: iteratorError.requestId,
                                body: iteratorError.body,
                                responseBody: iteratorError.responseBody,
                                stack: process.env.NODE_ENV === 'development' ? iteratorError.stack : undefined
                            });
                            throw iteratorError;
                        }
                    }
                    else {
                        logger.info(`Fetching single page for Graph path: ${path}`);
                        responseData = await request.get();
                    }
                    break;
                case 'post':
                    responseData = await request.post(body ?? {});
                    break;
                case 'put':
                    responseData = await request.put(body ?? {});
                    break;
                case 'patch':
                    responseData = await request.patch(body ?? {});
                    break;
                case 'delete':
                    responseData = await request.delete(); // Delete often returns no body or 204
                    // Handle potential 204 No Content response
                    if (responseData === undefined || responseData === null) {
                        responseData = { status: "Success (No Content)" };
                    }
                    break;
                default:
                    throw new Error(`Unsupported method: ${method}`);
            }
            // Never hand out pre-authenticated download URLs from plain metadata calls (bblg fork 0.1.4).
            redactDownloadUrls(responseData);
            // Audit logging for sensitive operations
            if (['post', 'put', 'patch', 'delete'].includes(method.toLowerCase())) {
                logger.audit('GRAPH_API_OPERATION', {
                    action: method.toUpperCase(),
                    targetResource: path,
                    result: 'SUCCESS',
                    metadata: {
                        apiVersion: effectiveGraphApiVersion,
                        hasBody: !!body,
                        fetchAll
                    }
                });
            }
        } // --- Azure Resource Management Logic (using direct fetch) ---
        else { // apiType === 'azure'
            if (!authManager) {
                throw new Error("Auth manager not initialized");
            }
            determinedUrl = AZURE_MANAGEMENT_ORIGIN; // For error reporting
            // Acquire token for Azure RM
            const azureCredential = authManager.getAzureCredential();
            const tokenResponse = await azureCredential.getToken("https://management.azure.com/.default");
            if (!tokenResponse || !tokenResponse.token) {
                throw new Error("Failed to acquire Azure access token");
            }
            // Construct the URL (similar to previous implementation)
            let url = determinedUrl;
            if (subscriptionId) {
                url += `/subscriptions/${subscriptionId}`;
            }
            url += path;
            if (!apiVersion) {
                throw new Error("API version is required for Azure Resource Management queries");
            }
            const urlParams = new URLSearchParams({ 'api-version': apiVersion });
            if (queryParams) {
                for (const [key, value] of Object.entries(queryParams)) {
                    urlParams.append(String(key), String(value));
                }
            }
            url += `?${urlParams.toString()}`;
            // Prepare request options
            const headers = {
                'Authorization': `Bearer ${tokenResponse.token}`,
                'Content-Type': 'application/json'
            };
            const requestOptions = {
                method: method.toUpperCase(),
                headers: headers
            };
            if (["POST", "PUT", "PATCH"].includes(method.toUpperCase())) {
                requestOptions.body = body ? JSON.stringify(body) : JSON.stringify({});
            }
            // --- Pagination Logic for Azure RM (Manual Fetch) ---
            if (fetchAll && method === 'get') {
                logger.info(`Fetching all pages for Azure RM starting from: ${url}`);
                let allValues = [];
                let currentUrl = url;
                let azurePageCount = 0;
                let azureTruncated = false;
                while (currentUrl) {
                    if (allValues.length >= MAX_FETCH_ALL_ITEMS || azurePageCount >= MAX_FETCH_ALL_PAGES) {
                        azureTruncated = true;
                        break;
                    }
                    azurePageCount++;
                    logger.info(`Fetching Azure RM page: ${currentUrl}`);
                    // Re-acquire token for each page (Azure tokens might expire)
                    const azureCredential = authManager.getAzureCredential();
                    const currentPageTokenResponse = await azureCredential.getToken("https://management.azure.com/.default");
                    if (!currentPageTokenResponse || !currentPageTokenResponse.token) {
                        throw new Error("Failed to acquire Azure access token during pagination");
                    }
                    const currentPageHeaders = { ...headers, 'Authorization': `Bearer ${currentPageTokenResponse.token}` };
                    const currentPageRequestOptions = { method: 'GET', headers: currentPageHeaders };
                    // The bearer token goes out with this request: the origin must be exactly ARM.
                    assertRequestOrigin(currentUrl, AZURE_MANAGEMENT_ORIGIN);
                    const pageResponse = await fetch(currentUrl, currentPageRequestOptions);
                    const pageText = await pageResponse.text();
                    let pageData;
                    try {
                        pageData = pageText ? JSON.parse(pageText) : {};
                    }
                    catch (e) {
                        logger.error(`Failed to parse JSON from Azure RM page: ${currentUrl}`, pageText);
                        pageData = { rawResponse: pageText };
                    }
                    if (!pageResponse.ok) {
                        logger.error(`API error on Azure RM page ${currentUrl}:`, pageData);
                        throw new Error(`API error (${pageResponse.status}) during Azure RM pagination on ${currentUrl}: ${JSON.stringify(pageData)}`);
                    }
                    if (pageData.value && Array.isArray(pageData.value)) {
                        allValues = allValues.concat(pageData.value);
                    }
                    else if (currentUrl === url && !pageData.nextLink) {
                        allValues.push(pageData);
                    }
                    else if (currentUrl !== url) {
                        logger.info(`[Warning] Azure RM response from ${currentUrl} did not contain a 'value' array.`);
                    }
                    // Validate nextLink to prevent SSRF attacks
                    const rawNextLink = pageData.nextLink || null;
                    if (rawNextLink) {
                        try {
                            const nextUrl = new URL(rawNextLink);
                            if (nextUrl.origin !== 'https://management.azure.com') {
                                logger.warn('SSRF protection: Blocked suspicious nextLink', { nextLink: rawNextLink });
                                currentUrl = null;
                            }
                            else {
                                currentUrl = rawNextLink;
                            }
                        }
                        catch {
                            logger.warn('SSRF protection: Invalid nextLink URL', { nextLink: rawNextLink });
                            currentUrl = null;
                        }
                    }
                    else {
                        currentUrl = null;
                    }
                }
                if (allValues.length > MAX_FETCH_ALL_ITEMS) {
                    allValues.length = MAX_FETCH_ALL_ITEMS;
                    azureTruncated = true;
                }
                responseData = {
                    allValues: allValues,
                    ...(azureTruncated && {
                        truncated: true,
                        note: `Stopped after ${allValues.length} items across ${azurePageCount} pages (server caps: MAX_FETCH_ALL_ITEMS=${MAX_FETCH_ALL_ITEMS}, MAX_FETCH_ALL_PAGES=${MAX_FETCH_ALL_PAGES}).`
                    })
                };
                logger.info(`Finished fetching Azure RM pages. Total items: ${allValues.length}, pages: ${azurePageCount}, truncated: ${azureTruncated}`);
            }
            else {
                // Single page fetch for Azure RM
                logger.info(`Fetching single page for Azure RM: ${url}`);
                // The bearer token goes out with this request: the origin must be exactly ARM.
                assertRequestOrigin(url, AZURE_MANAGEMENT_ORIGIN);
                const apiResponse = await fetch(url, requestOptions);
                const responseText = await apiResponse.text();
                try {
                    responseData = responseText ? JSON.parse(responseText) : {};
                }
                catch (e) {
                    logger.error(`Failed to parse JSON from single Azure RM page: ${url}`, responseText);
                    responseData = { rawResponse: responseText };
                }
                if (!apiResponse.ok) {
                    logger.error(`API error for Azure RM ${method} ${path}:`, responseData);
                    throw new Error(`API error (${apiResponse.status}) for Azure RM: ${JSON.stringify(responseData)}`);
                }
            }
            // Audit logging for Azure sensitive operations
            if (['post', 'put', 'patch', 'delete'].includes(method.toLowerCase())) {
                logger.audit('AZURE_RM_OPERATION', {
                    action: method.toUpperCase(),
                    targetResource: path,
                    result: 'SUCCESS',
                    metadata: {
                        apiVersion,
                        subscriptionId,
                        hasBody: !!body,
                        fetchAll
                    }
                });
            }
        }
        // --- Format and Return Result ---
        // For all requests, format as text
        let resultText = `Result for ${apiType} API (${apiType === 'graph' ? effectiveGraphApiVersion : apiVersion}) - ${method} ${path}:\n\n`;
        resultText += JSON.stringify(responseData, null, 2); // responseData already contains the correct structure for fetchAll Graph case
        // Add pagination note if applicable (only for single page GET)
        if (!fetchAll && method === 'get') {
            const nextLinkKey = apiType === 'graph' ? '@odata.nextLink' : 'nextLink';
            if (responseData && responseData[nextLinkKey]) { // Added check for responseData existence
                resultText += `\n\nNote: More results are available. To retrieve all pages, add the parameter 'fetchAll: true' to your request.`;
            }
        }
        const response = {
            content: [{ type: "text", text: resultText }],
        };
        return addSecurityHeaders(response);
    }
    catch (error) {
        // Extract comprehensive error details
        const errorDetails = {
            message: error.message || error.toString() || 'Unknown error',
            statusCode: error.statusCode,
            code: error.code,
            requestId: error.requestId || error.headers?.['request-id'],
            body: error.body,
            responseBody: error.responseBody,
            response: error.response,
            // For Graph SDK specific errors
            graphError: error.responseBody || error.response?.body,
            stack: process.env.NODE_ENV === 'development' ? error.stack : undefined,
            raw: error
        };
        // Log with full details
        logger.error(`Error in microsoft-graph tool (apiType: ${apiType}, path: ${path}, method: ${method}):`, errorDetails);
        // Try to determine the base URL even in case of error
        if (!determinedUrl) {
            determinedUrl = apiType === 'graph'
                ? `https://graph.microsoft.com/${effectiveGraphApiVersion || defaultGraphApiVersion}`
                : "https://management.azure.com";
        }
        // Prepare user-friendly error response
        let userErrorMessage = errorDetails.message;
        let errorBody = 'N/A';
        // Try to extract meaningful error body
        if (errorDetails.responseBody) {
            errorBody = typeof errorDetails.responseBody === 'string'
                ? errorDetails.responseBody
                : JSON.stringify(errorDetails.responseBody, null, 2);
        }
        else if (errorDetails.body) {
            errorBody = typeof errorDetails.body === 'string'
                ? errorDetails.body
                : JSON.stringify(errorDetails.body, null, 2);
        }
        else if (errorDetails.graphError) {
            errorBody = typeof errorDetails.graphError === 'string'
                ? errorDetails.graphError
                : JSON.stringify(errorDetails.graphError, null, 2);
        }
        // In production, sanitize error details to prevent information leakage
        const isDevelopment = process.env.NODE_ENV === 'development';
        const errorPayload = isDevelopment ? {
            error: userErrorMessage,
            statusCode: errorDetails.statusCode || 'N/A',
            errorCode: errorDetails.code || 'N/A',
            requestId: errorDetails.requestId || 'N/A',
            errorBody: errorBody,
            attemptedBaseUrl: determinedUrl
        } : {
            error: userErrorMessage,
            statusCode: errorDetails.statusCode || 'N/A',
            errorCode: errorDetails.code || 'N/A',
            requestId: errorDetails.requestId || 'N/A'
        };
        const errorResponse = {
            content: [{
                    type: "text",
                    text: JSON.stringify(errorPayload, null, 2),
                }],
            isError: true
        };
        return addSecurityHeaders(errorResponse);
    }
});
// Add token management tools
server.tool("set-access-token", "Set or update the access token for Microsoft Graph authentication. Use this when the MCP Client has obtained a fresh token through interactive authentication.", setAccessTokenSchema, async ({ accessToken, expiresOn, confirm, confirmToken }) => {
    try {
        // Changing identity is a control-plane action: blocked under shutdown, allowed in read-only.
        await policyGuard.enforce({ tool: 'set-access-token', verb: 'read', resource: 'auth:access-token' });
        const expirationDate = expiresOn ? new Date(expiresOn) : undefined;
        if (authManager?.getAuthMode() === AuthMode.ClientProvidedToken) {
            // A misconfigured client-token mode refuses every token; say so before asking anyone to confirm.
            if (authInitialization.state === 'failed') {
                return {
                    content: [{ type: "text", text: `Error setting access token: ${authInitialization.error}` }],
                    isError: true
                };
            }
            // Replacing the identity that every later call runs as is confirmed like a write. The preview
            // carries a fingerprint of this exact token, so an approval cannot be reused for another one.
            const preview = {
                tool: 'set-access-token',
                operations: [{
                        index: 1,
                        operation: 'replace_identity',
                        target: { id: 'auth:access-token', name: 'replace the server identity', kind: 'identity' },
                        parameters: compact({
                            tokenFingerprint: crypto.createHash('sha256').update(accessToken).digest('hex').slice(0, 12),
                            expiresOn
                        })
                    }],
            };
            const outcome = await confirmWrite(preview, { confirm, confirmToken }, elicitor, confirmOptions);
            if (!outcome.approved) {
                return { content: [{ type: "text", text: explainOutcome(outcome) }] };
            }
            await authManager.updateAccessToken(accessToken, expirationDate);
            // Reinitialize the Graph client with the new token
            const authProvider = authManager.getGraphAuthProvider();
            graphClient = createGraphClient(authProvider);
            logger.audit('TOKEN_UPDATED', {
                action: 'SET_ACCESS_TOKEN',
                result: 'SUCCESS',
                targetResource: 'auth:access-token',
                metadata: {
                    hasExpiration: !!expiresOn,
                    authMode: authManager?.getAuthMode()
                }
            });
            // Identity changed: drop everything cached under the previous identity.
            paginationCache.clear();
            siteCache.clear();
            return {
                content: [{
                        type: "text",
                        text: "Access token updated successfully. You can now make Microsoft Graph requests on behalf of the authenticated user."
                    }],
            };
        }
        else {
            return {
                content: [{
                        type: "text",
                        text: "Error: MCP Server is not configured for client-provided token authentication. Set USE_CLIENT_TOKEN=true in environment variables."
                    }],
                isError: true
            };
        }
    }
    catch (error) {
        logger.error("Error setting access token:", error);
        return {
            content: [{
                    type: "text",
                    text: `Error setting access token: ${error.message}`
                }],
            isError: true
        };
    }
});
server.tool("get-auth-status", "Check the current authentication status and mode of the MCP Server and also returns the current graph permission scopes of the access token for the current session.", getAuthStatusSchema, async () => {
    try {
        const authMode = authManager?.getAuthMode() || "Not initialized";
        // isReady: the server process is up and accepting tool calls.
        // isAuthenticated: a usable, unexpired credential exists. These are different things.
        const isReady = authManager !== null;
        const tokenStatus = authManager
            ? await authManager.getTokenStatus()
            : { hasCredential: false, isExpired: true };
        const isAuthenticated = tokenStatus.hasCredential && !tokenStatus.isExpired;
        const pendingAuth = authManager?.getPendingAuthInfo() ?? null;
        // Include Zero Trust monitoring status
        const zeroTrustStatus = process.env.ENABLE_ZERO_TRUST_MONITORING !== 'false'
            ? zeroTrustMonitor.getBaselineStats()
            : { enabled: false };
        return {
            content: [{
                    type: "text",
                    text: JSON.stringify({
                        authMode,
                        isReady,
                        isAuthenticated,
                        supportsTokenUpdates: authMode === AuthMode.ClientProvidedToken,
                        tokenStatus: tokenStatus,
                        pendingAuth,
                        loginRequired: tokenStatus.loginRequired ?? false,
                        hint: tokenStatus.loginRequired
                            ? "No saved Microsoft session. Run the 'login' tool once to sign in; other server instances will reuse the result."
                            : undefined,
                        initialization: authInitialization,
                        zeroTrust: zeroTrustStatus,
                        timestamp: new Date().toISOString()
                    }, null, 2)
                }],
        };
    }
    catch (error) {
        return {
            content: [{
                    type: "text",
                    text: `Error checking auth status: ${error.message}`
                }],
            isError: true
        };
    }
});
// Explicit interactive sign-in. Only this tool opens a browser or starts a device-code flow.
server.tool("login", "Sign in to Microsoft interactively (interactive auth mode only). Opens a browser by default, or use the device-code flow for headless setups. Run once; the session is saved in OS-protected storage and reused by every server instance.", {
    useDeviceCode: z.boolean().optional().describe("Use the device-code flow instead of a browser. Retrieve the code via get-auth-status while this call is pending.")
}, async ({ useDeviceCode }) => {
    try {
        // Control-plane action: blocked under shutdown, allowed in read-only.
        await policyGuard.enforce({ tool: 'login', verb: 'read', resource: 'auth:login' });
        if (!authManager) {
            throw new Error("Authentication not initialized");
        }
        const status = await authManager.login({ useDeviceCode: !!useDeviceCode });
        // Always rebuild: a device-code login replaces the credential behind the manager, and a
        // client built over the previous one would keep answering "Not signed in".
        graphClient = createGraphClient(authManager.getGraphAuthProvider());
        paginationCache.clear();
        siteCache.clear();
        logger.audit('LOGIN', { action: 'INTERACTIVE_LOGIN', result: 'SUCCESS', targetResource: 'auth:login',
            metadata: { deviceCode: !!useDeviceCode } });
        return {
            content: [{
                    type: "text",
                    text: JSON.stringify({ signedIn: true, expiresOn: status.expiresOn, scopes: status.scopes }, null, 2)
                }],
        };
    }
    catch (error) {
        logger.audit('LOGIN', { action: 'INTERACTIVE_LOGIN', result: 'FAILURE', targetResource: 'auth:login' });
        return {
            content: [{ type: "text", text: `Login failed: ${error.message}` }],
            isError: true
        };
    }
});
// Explicit sign-out. Forgets the persisted session and blocks the current token locally.
server.tool("logout", "Sign out of the Microsoft session (interactive auth mode only). Blocks the current token locally and removes this app's saved session from OS-protected storage, so every server instance will require 'login' again. Optionally also revokes your refresh tokens at Microsoft, which signs you out of ALL applications.", {
    revokeMicrosoftSessions: z.boolean().optional().describe("Also revoke your sign-in sessions at Microsoft (signs you out of every app; requires a token permitted to revoke sessions).")
}, async ({ revokeMicrosoftSessions }) => {
    try {
        await policyGuard.enforce({ tool: 'logout', verb: 'read', resource: 'auth:logout' });
        if (!authManager) {
            throw new Error("Authentication not initialized");
        }
        const result = await authManager.logout({ revokeMicrosoftSessions: !!revokeMicrosoftSessions }, async () => {
            if (!graphClient)
                throw new Error("Graph client not initialized");
            await graphClient.api('/me/revokeSignInSessions').post({});
        });
        // The manager is now gated (login required); point the client at the current credential
        // so nothing keeps calling through a wrapper built around the pre-logout one.
        graphClient = createGraphClient(authManager.getGraphAuthProvider());
        paginationCache.clear();
        siteCache.clear();
        logger.audit('LOGOUT', { action: 'INTERACTIVE_LOGOUT', result: 'SUCCESS', targetResource: 'auth:logout',
            metadata: { ...result } });
        const lines = [
            `Signed out. Cleared: ${result.localSessionCleared.join(', ') || 'in-memory session only'}.`,
            result.tokenBlockedLocally ? 'The current access token is blocked locally until it expires.' : 'No live token was held.',
            result.microsoftSessionsRevoked === true ? 'Microsoft sign-in sessions revoked: you are signed out of all applications.'
                : result.microsoftSessionsRevoked === 'not_permitted' ? 'Microsoft session revocation was refused: the token lacks permission to revoke sessions. Local sign-out completed.'
                    : result.microsoftSessionsRevoked === 'failed' ? `Microsoft session revocation failed: ${result.microsoftError}. Local sign-out completed.`
                        : 'Microsoft sessions were not revoked; existing tokens in other apps remain valid until they expire.',
            "Run the 'login' tool to sign in again."
        ];
        return { content: [{ type: "text", text: lines.join('\n') }] };
    }
    catch (error) {
        logger.audit('LOGOUT', { action: 'INTERACTIVE_LOGOUT', result: 'FAILURE', targetResource: 'auth:logout' });
        return { content: [{ type: "text", text: `Logout failed: ${error.message}` }], isError: true };
    }
});
// Health check endpoint
server.tool("health-check", "Check the health status of the MCP Server including authentication, Graph API connectivity, emergency controls, and security systems", {}, // No parameters needed
async () => {
    try {
        const tokenStatus = authManager
            ? await authManager.getTokenStatus()
            : { hasCredential: false, isExpired: true };
        const emergencyStatus = emergencyControls.getStatus();
        const ztStats = zeroTrustMonitor.getBaselineStats();
        const revocationStats = tokenRevocationManager.getStats();
        const health = await computeHealth({
            version: SERVER_VERSION,
            authMode: authManager?.getAuthMode(),
            tokenStatus,
            initialization: authInitialization,
            emergency: { mode: emergencyStatus.mode, isActive: emergencyStatus.isActive },
            rateLimitRemaining: rateLimiter.getRemainingRequests(getClientIdentifier({})),
            revocation: { totalRevoked: revocationStats.totalRevoked, activeRevocations: revocationStats.activeRevocations },
            zeroTrust: { mode: ztStats.mode, level: ztStats.level, dataPoints: ztStats.baselineDataPoints },
            // The probe is a resource access like any other: it goes through the policy guard and
            // the revocation-checked client. computeHealth already skips it outside normal mode.
            probeGraph: async () => {
                await policyGuard.enforce({ tool: 'health-check', verb: 'read', resource: '/me' });
                if (!graphClient)
                    throw new Error('Graph client not initialized');
                await graphClient.api('/me').select('id').get();
            },
        });
        // Add security configuration
        health.security = {
            loggingEnabled: process.env.ENABLE_LOGGING === 'true',
            auditLogEnabled: process.env.ENABLE_AUDIT_LOG === 'true',
            strictPermissionMode: process.env.STRICT_PERMISSION_MODE === 'true',
            environment: process.env.NODE_ENV || 'development'
        };
        const response = {
            content: [{
                    type: "text",
                    text: JSON.stringify(health, null, 2)
                }],
        };
        return addSecurityHeaders(response);
    }
    catch (error) {
        logger.error("Health check failed", error);
        const errorResponse = {
            content: [{
                    type: "text",
                    text: JSON.stringify({
                        status: 'error',
                        error: error.message,
                        timestamp: new Date().toISOString()
                    }, null, 2)
                }],
            isError: true
        };
        return addSecurityHeaders(errorResponse);
    }
});
// Add tool for requesting additional Graph permissions
server.tool("add-graph-permission", "Request additional Microsoft Graph permission scopes by performing a fresh interactive sign-in. This tool only works in interactive authentication mode and should be used if any Graph API call returns permissions related errors.", addGraphPermissionSchema, async ({ scopes }) => {
    try {
        // Re-authentication is a control-plane action: blocked under shutdown, allowed in read-only.
        await policyGuard.enforce({ tool: 'add-graph-permission', verb: 'read', resource: 'auth:scopes' });
        // Check if we're in interactive mode
        if (!authManager || authManager.getAuthMode() !== AuthMode.Interactive) {
            const currentMode = authManager?.getAuthMode() || "Not initialized";
            const clientId = process.env.CLIENT_ID;
            let errorMessage = `Error: add-graph-permission tool is only available in interactive authentication mode. Current mode: ${currentMode}.\n\n`;
            if (currentMode === AuthMode.ClientCredentials) {
                errorMessage += `📋 To add permissions in Client Credentials mode:\n`;
                errorMessage += `1. Open the Microsoft Entra admin center (https://entra.microsoft.com)\n`;
                errorMessage += `2. Navigate to Applications > App registrations\n`;
                errorMessage += `3. Find your application${clientId ? ` (Client ID: ${clientId})` : ''}\n`;
                errorMessage += `4. Go to API permissions\n`;
                errorMessage += `5. Click "Add a permission" and select Microsoft Graph\n`;
                errorMessage += `6. Choose "Application permissions" and add the required scopes:\n`;
                errorMessage += `   ${scopes.map((scope) => `• ${scope}`).join('\n   ')}\n`;
                errorMessage += `7. Click "Grant admin consent" to approve the permissions\n`;
                errorMessage += `8. Restart the MCP server to use the new permissions`;
            }
            else if (currentMode === AuthMode.ClientProvidedToken) {
                errorMessage += `📋 To add permissions in Client Provided Token mode:\n`;
                errorMessage += `1. Obtain a new access token that includes the required scopes:\n`;
                errorMessage += `   ${scopes.map((scope) => `• ${scope}`).join('\n   ')}\n`;
                errorMessage += `2. When obtaining the token, ensure these scopes are included in the consent prompt\n`;
                errorMessage += `3. Use the set-access-token tool to update the server with the new token\n`;
                errorMessage += `4. The new token will include the additional permissions`;
            }
            else {
                errorMessage += `To use interactive permission requests, set USE_INTERACTIVE=true in environment variables and restart the server.`;
            }
            return {
                content: [{
                        type: "text",
                        text: errorMessage
                    }],
                isError: true
            };
        }
        // Validate scopes array
        if (!scopes || scopes.length === 0) {
            return {
                content: [{
                        type: "text",
                        text: "Error: At least one permission scope must be specified."
                    }],
                isError: true
            };
        }
        // Validate scope format (basic validation)
        const invalidScopes = scopes.filter((scope) => !scope.includes('.') || scope.trim() !== scope);
        if (invalidScopes.length > 0) {
            return {
                content: [{
                        type: "text",
                        text: `Error: Invalid scope format detected: ${invalidScopes.join(', ')}. Scopes should be in format like 'User.Read' or 'Mail.ReadWrite'.`
                    }],
                isError: true
            };
        }
        logger.info(`Requesting additional Graph permissions: ${scopes.join(', ')}`);
        // Get current configuration - CLIENT_ID must be explicitly configured
        const tenantId = process.env.TENANT_ID || DefaultTenantId;
        const clientId = process.env.CLIENT_ID;
        if (!clientId) {
            throw new Error("CLIENT_ID environment variable is required for adding Graph permissions.");
        }
        const redirectUri = process.env.REDIRECT_URI || DefaultRedirectUri;
        logger.info(`Using tenant ID: ${tenantId}, client ID: ${clientId} for interactive authentication`);
        // Reuse the securely persisted account while requesting any additional consent.
        const { createPersistentLogin } = await import("./persistent-login.js");
        // Request token with the new scopes - this will trigger interactive authentication
        const requestedScopes = scopes.map((scope) => `https://graph.microsoft.com/${scope}`);
        const scopeString = requestedScopes.join(' ');
        logger.info(`Requesting fresh token with scopes: ${scopeString}`);
        logger.info(`Requesting Additional Graph Permissions: ${scopes.join(', ')}`);
        logger.info(`User will be prompted to sign in to grant these permissions.`);
        let newCredential = await createPersistentLogin({ tenantId, clientId, redirectUri });
        let tokenResponse;
        try {
            tokenResponse = await newCredential.login(requestedScopes);
        }
        catch (error) {
            // Fallback to Device Code flow
            logger.info("Interactive browser failed, falling back to device code flow");
            newCredential = await createPersistentLogin({
                tenantId: tenantId,
                clientId: clientId,
                redirectUri,
                deviceCode: (info) => {
                    logger.info(`Additional Permissions Required - Visit: ${info.verificationUri} - Code: ${info.userCode}`);
                    logger.info(`Requested scopes: ${scopes.join(', ')}`);
                    return Promise.resolve();
                },
            });
            // Request token with device code credential
            tokenResponse = await newCredential.login(requestedScopes);
        }
        if (!tokenResponse) {
            return {
                content: [{
                        type: "text",
                        text: "Error: Failed to acquire access token with the requested scopes. Please check your permissions and try again."
                    }],
                isError: true
            };
        }
        // Create a completely new auth manager instance with the updated credential
        const authConfig = {
            mode: AuthMode.Interactive,
            tenantId,
            clientId,
            redirectUri
        };
        // Build and verify the replacement pair locally first. If verification fails the
        // previous manager and client stay live and consistent with each other.
        const replacementManager = await AuthManager.createWithCredential(authConfig, newCredential);
        const replacementClient = createGraphClient(replacementManager.getGraphAuthProvider());
        // Publish both together, then drop everything cached under the previous identity.
        authManager = replacementManager;
        graphClient = replacementClient;
        paginationCache.clear();
        siteCache.clear();
        // Get the token status to show the new scopes
        const tokenStatus = await authManager.getTokenStatus();
        logger.info(`Successfully acquired fresh token with additional scopes: ${scopes.join(', ')}`);
        return {
            content: [{
                    type: "text",
                    text: JSON.stringify({
                        message: "Successfully acquired additional Microsoft Graph permissions with fresh authentication",
                        requestedScopes: scopes,
                        tokenStatus: tokenStatus,
                        note: "A fresh sign-in was performed to ensure the new permissions are properly granted",
                        timestamp: new Date().toISOString()
                    }, null, 2)
                }],
        };
    }
    catch (error) {
        logger.error("Error requesting additional Graph permissions:", error);
        return {
            content: [{
                    type: "text",
                    text: `Error requesting additional permissions: ${error.message}`
                }],
            isError: true
        };
    }
});
// SharePoint Site-Scoped File Operations Tool
server.tool("sharepoint-site-files", "Comprehensive tool for finding, searching, and working with files within a specific SharePoint site. Supports advanced search, filtering, folder navigation, and file metadata operations.", sharePointSiteFilesSchema, (params, extra) => handleSiteFiles(params, extra, {}));
async function handleSiteFiles(params, _extra, ctx) {
    try {
        // A dry run of a write changes nothing, so it is permitted in read-only mode.
        await policyGuard.enforce({
            tool: 'sharepoint-site-files',
            verb: params.dryRun ? 'read' : siteFilesVerb(params.operation),
            resource: `site:${params.siteName}`
        });
        // Check and auto-initialize Graph client if needed for SharePoint operations
        if (!graphClient && authManager) {
            if (authManager.getAuthMode() === AuthMode.ClientProvidedToken) {
                const reinitializedFromCache = await authManager.tryInitializeFromCache();
                if (reinitializedFromCache) {
                    const authProvider = authManager.getGraphAuthProvider();
                    graphClient = createGraphClient(authProvider);
                    logger.info("Graph client auto-initialized from cached token for SharePoint operation");
                }
            }
        }
        if (!graphClient) {
            if (authManager?.getAuthMode() === AuthMode.ClientProvidedToken) {
                throw new Error("Authentication not initialized. Please use the 'set-access-token' tool first to provide an access token.");
            }
            else {
                throw new Error("Graph client not initialized. Check authentication configuration.");
            }
        }
        const { siteName, operation, searchQuery, fileType, folderPath, modifiedAfter, modifiedBefore, createdBy, minSize, maxSize, maxResults, orderBy, descending, fileId, includeSubfolders, includePermissions, 
        // New parameters for enhanced features
        useAdvancedSearch, pageNumber, pageSize, 
        // CRUD operation parameters
        newName, destinationPath, folderName, content, contentEncoding, daysBack, dryRun, confirm, confirmToken, operations, continueOnError } = params;
        // Security: folderPath is validated (no traversal, no URL delimiters) and then percent-encoded
        // per segment wherever it is placed inside a Graph URL (F10).
        const safeFolderPath = folderPath ? sanitizePath(folderPath) : folderPath;
        const encodedFolderPath = safeFolderPath ? encodeDrivePath(safeFolderPath) : safeFolderPath;
        logger.info(`SharePoint site operation: ${operation} on site: ${siteName}`);
        // findSite is now imported from ./site-utils.js
        // File results are shaped by formatDriveItem (./drive-item.js): no pre-authenticated download URL (F9).
        const formatFileResult = (item) => formatDriveItem(item, { includePermissions });
        // Helper function to build OData filter
        function buildSearchFilter() {
            const filters = [];
            if (fileType) {
                const extensions = fileType.split(',').map((ext) => ext.trim().toLowerCase());
                const extFilters = extensions.map((ext) => `endswith(name, '.${ext}')`);
                if (extFilters.length > 1) {
                    filters.push(`(${extFilters.join(' or ')})`);
                }
                else {
                    filters.push(extFilters[0]);
                }
            }
            if (modifiedAfter) {
                filters.push(`lastModifiedDateTime ge ${modifiedAfter}`);
            }
            if (modifiedBefore) {
                filters.push(`lastModifiedDateTime le ${modifiedBefore}`);
            }
            if (minSize) {
                filters.push(`size ge ${minSize}`);
            }
            if (maxSize) {
                filters.push(`size le ${maxSize}`);
            }
            // Note: 'file ne null' filter is not supported on /children endpoints
            // for many SharePoint drive types, so we filter folders client-side instead
            return filters.length > 0 ? filters.join(' and ') : undefined;
        }
        // Find the site first
        let site;
        try {
            // Writes must target an exactly identified site; reads may use fuzzy matching.
            const isWrite = siteFilesVerb(operation) === 'write';
            site = await findSite(siteName, graphClient, siteCache, { exact: isWrite });
            logger.info(`Found SharePoint site: ${site.displayName} (${site.id})`);
        }
        catch (findError) {
            logger.error(`Failed to find site '${siteName}':`, findError);
            throw findError; // the resolver's message already lists candidates or the real cause
        }
        let result = {};
        if (dryRun && operation !== 'batch' && siteFilesVerb(operation) === 'write') {
            // Resolve everything the write would touch and stop. Nothing is changed.
            let target = null;
            if (fileId) {
                const item = await throttledRetry(() => graphClient.api(`/sites/${site.id}/drive/items/${fileId}`).select('id,name,webUrl,size,folder,file,parentReference,lastModifiedDateTime').get());
                target = { id: item.id, name: item.name, webUrl: item.webUrl, size: item.size,
                    kind: item.folder ? 'folder' : 'file', path: item.parentReference?.path?.replace('/drive/root:', '') || '/',
                    lastModified: item.lastModifiedDateTime };
            }
            const preview = {
                dryRun: true,
                operation,
                site: { id: site.id, displayName: site.displayName, webUrl: site.webUrl },
                target,
                parameters: { folderPath, folderName, newName, destinationPath, ...(content !== undefined ? describeContent(content, contentEncoding ?? 'text') : {}) },
                note: 'No changes were made. Re-run without dryRun to apply.'
            };
            return { content: [{ type: "text", text: JSON.stringify(preview, null, 2) }] };
        }
        if (operation === 'batch') {
            if (!operations || operations.length === 0) {
                throw new Error("batch requires a non-empty 'operations' array");
            }
            // Resolve every entry before anything runs; one unresolvable entry refuses the whole batch.
            const preview = { tool: 'sharepoint-site-files', site: { id: site.id, displayName: site.displayName, webUrl: site.webUrl }, operations: [] };
            for (const [i, op] of operations.entries()) {
                const target = op.fileId ? await resolveFileTarget(site.id, op.fileId) : null;
                if (!op.fileId && op.operation !== 'create_folder') {
                    throw new Error(`batch entry ${i + 1} (${op.operation}) requires fileId`);
                }
                preview.operations.push({ index: i + 1, operation: op.operation, target,
                    parameters: compact({ folderPath: op.folderPath, folderName: op.folderName, newName: op.newName, destinationPath: op.destinationPath,
                        ...(op.content !== undefined ? describeContent(op.content, op.contentEncoding ?? 'text') : {}) }) });
            }
            if (dryRun) {
                return { content: [{ type: "text", text: `${renderPreview(preview)}\n\nDry run: nothing was changed.` }] };
            }
            const outcome = await confirmWrite(preview, { confirm, confirmToken }, elicitor, confirmOptions);
            if (!outcome.approved) {
                return { content: [{ type: "text", text: explainOutcome(outcome) }] };
            }
            const batchId = `batch-${Date.now().toString(36)}`;
            const outcomes = [];
            for (const [i, op] of operations.entries()) {
                // Exactly what was previewed: the entry's own fields and the site. No outer-call leakage.
                const single = await handleSiteFiles({ siteName, operation: op.operation, fileId: op.fileId, folderPath: op.folderPath, folderName: op.folderName,
                    newName: op.newName, destinationPath: op.destinationPath, content: op.content, contentEncoding: op.contentEncoding,
                    dryRun: false }, _extra, { skipConfirm: true });
                const text = single?.content?.[0]?.text ?? '';
                const failed = single?.isError === true;
                outcomes.push({ index: i + 1, operation: op.operation, fileId: op.fileId, status: failed ? 'failed' : 'done', detail: text.slice(0, 500) });
                logger.audit('BATCH_ENTRY', { action: op.operation.toUpperCase(), result: failed ? 'FAILURE' : 'SUCCESS', targetResource: `file:${op.fileId ?? op.folderName}`, metadata: { batchId, index: i + 1, siteName } });
                if (failed && !continueOnError) {
                    outcomes.push({ note: `Stopped after entry ${i + 1} failed. ${operations.length - i - 1} entr${operations.length - i - 1 === 1 ? 'y' : 'ies'} not run.` });
                    break;
                }
            }
            return { content: [{ type: "text", text: JSON.stringify({ batchId, site: preview.site, results: outcomes }, null, 2) }] };
        }
        if (siteFilesVerb(operation) === 'write' && !ctx.skipConfirm) {
            const target = fileId ? await resolveFileTarget(site.id, fileId) : null;
            const preview = {
                tool: 'sharepoint-site-files',
                site: { id: site.id, displayName: site.displayName, webUrl: site.webUrl },
                operations: [{ index: 1, operation, target, parameters: compact({ folderPath, folderName, newName, destinationPath,
                            ...(content !== undefined ? describeContent(content, contentEncoding ?? 'text') : {}) }) }],
            };
            const outcome = await confirmWrite(preview, { confirm, confirmToken }, elicitor, confirmOptions);
            if (!outcome.approved) {
                return { content: [{ type: "text", text: explainOutcome(outcome) }] };
            }
        }
        // Permission validation for destructive file operations
        const destructiveOps = ['delete', 'rename', 'copy', 'move', 'create_folder', 'update_content'];
        if (destructiveOps.includes(operation) && authManager) {
            const tokenStatus = await authManager.getTokenStatus();
            const scopes = tokenStatus.scopes || [];
            const permCheck = PermissionValidator.validateScopes('/drives', operation === 'delete' ? 'delete' : 'patch', scopes);
            if (!permCheck.allowed) {
                logger.warn('Permission denied for destructive file operation', {
                    operation,
                    reason: permCheck.reason,
                    requiredScopes: permCheck.requiredScopes
                });
                throw new Error(`Permission denied: ${permCheck.reason}. Required scopes: ${permCheck.requiredScopes?.join(', ')}`);
            }
        }
        // Perform the requested operation
        switch (operation) {
            case 'site_info': {
                // Get detailed site information
                const [lists, drives] = await Promise.all([
                    graphClient.api(`/sites/${site.id}/lists`)
                        .top(10)
                        .select('id,name,displayName,description,createdDateTime')
                        .get()
                        .catch(() => ({ value: [] })),
                    graphClient.api(`/sites/${site.id}/drives`)
                        .select('id,name,description,driveType,quota')
                        .get()
                        .catch(() => ({ value: [] }))
                ]);
                result = {
                    site: {
                        id: site.id,
                        name: site.name,
                        displayName: site.displayName,
                        url: site.webUrl,
                        description: site.description,
                        created: site.createdDateTime
                    },
                    lists: lists.value?.map((list) => ({
                        name: list.displayName || list.name,
                        description: list.description,
                        created: list.createdDateTime
                    })),
                    documentLibraries: drives.value?.map((drive) => ({
                        name: drive.name,
                        type: drive.driveType,
                        quotaUsed: drive.quota?.used,
                        quotaTotal: drive.quota?.total,
                        quotaRemaining: drive.quota?.remaining
                    }))
                };
                break;
            }
            case 'search': {
                if (!searchQuery && !fileType) {
                    throw new Error("Search operation requires either searchQuery or fileType parameter");
                }
                // Try advanced search first if enabled and searchQuery is provided
                if (useAdvancedSearch && searchQuery) {
                    const enhanced = getEnhancedOps(graphClient);
                    try {
                        const searchResults = await enhanced.searchFiles({
                            query: searchQuery,
                            siteId: site.id,
                            folderPath: safeFolderPath,
                            fileTypes: fileType ? fileType.split(',').map(t => t.trim()) : undefined,
                            modifiedAfter: modifiedAfter ? new Date(modifiedAfter) : undefined,
                            modifiedBefore: modifiedBefore ? new Date(modifiedBefore) : undefined,
                            createdBy: createdBy,
                            minSize: minSize,
                            maxSize: maxSize,
                            maxResults: maxResults || 10, // Default to 10 results to prevent context overflow
                            includeContent: true
                        });
                        result = {
                            searchEngine: 'Microsoft Search API',
                            query: searchQuery,
                            totalResults: searchResults.totalResults,
                            hasMore: searchResults.hasMore,
                            suggestions: searchResults.suggestions,
                            files: searchResults.results
                        };
                        logger.info(`Advanced search completed: ${searchResults.totalResults} results`);
                        break; // Exit early if advanced search succeeds
                    }
                    catch (error) {
                        logger.warn(`Advanced search failed, falling back to basic search: ${error.message}`);
                        // Continue to basic search below
                    }
                }
                // Build the search query for basic search
                let searchTerm = searchQuery || '*';
                // Add file type to search if specified
                if (fileType && searchQuery) {
                    const extensions = fileType.split(',').map((ext) => ext.trim().toLowerCase());
                    searchTerm = `${searchQuery} AND (${extensions.map((ext) => `filetype:${ext}`).join(' OR ')})`;
                }
                else if (fileType && !searchQuery) {
                    const extensions = fileType.split(',').map((ext) => ext.trim().toLowerCase());
                    searchTerm = extensions.map((ext) => `filetype:${ext}`).join(' OR ');
                }
                // Determine the search scope
                let searchPath = `/sites/${site.id}/drive/root/search(q='${encodeSearchTerm(searchTerm)}')`;
                if (encodedFolderPath) {
                    // Search within specific folder
                    searchPath = `/sites/${site.id}/drive/root:/${encodedFolderPath}:/search(q='${encodeSearchTerm(searchTerm)}')`;
                }
                // Default to 10 results to prevent context overflow
                const searchLimit = Math.min(maxResults || 10, 999);
                let request = graphClient.api(searchPath)
                    .top(searchLimit)
                    .select(DRIVE_ITEM_LIST_SELECT);
                // Add ordering if not using search with query (search has its own relevance ordering)
                if (!searchQuery && orderBy) {
                    request = request.orderby(`${{ 'name': 'name', 'modified': 'lastModifiedDateTime', 'size': 'size', 'createdDateTime': 'createdDateTime' }[orderBy || 'name'] || 'name'} ${descending ? 'desc' : 'asc'}`);
                }
                const response = await request.get();
                // Check for more results
                const hasMore = response['@odata.nextLink'] ? true : false;
                result = {
                    searchQuery: searchTerm,
                    location: safeFolderPath || 'Entire site',
                    itemsReturned: response.value.length,
                    hasMore: hasMore,
                    files: response.value.map((item) => formatFileResult(item))
                };
                // Add continuation info if there are more results
                if (hasMore) {
                    result.continuation = {
                        message: `Showing first ${response.value.length} results. More results available.`,
                        suggestion: "Increase maxResults parameter or refine your search to get more specific results.",
                        tip: "Use fileType, modifiedAfter, or other filters to narrow down results."
                    };
                }
                // Add summary for large result sets
                if (response.value.length >= 10) {
                    const fileCount = response.value.filter((item) => item.file).length;
                    const folderCount = response.value.filter((item) => item.folder).length;
                    result.summary = {
                        files: fileCount,
                        folders: folderCount,
                        note: "Consider using more specific search terms or filters to reduce results."
                    };
                }
                break;
            }
            case 'list': {
                // Check if pagination is requested
                if (pageNumber && pageNumber > 0) {
                    const enhanced = getEnhancedOps(graphClient);
                    try {
                        // Get specific page using pagination
                        const pageResults = await enhanced.paginator.getPage({
                            siteId: site.id,
                            folderPath: safeFolderPath,
                            filter: buildSearchFilter(),
                            orderBy: `${{ 'name': 'name', 'modified': 'lastModifiedDateTime', 'size': 'size', 'createdDateTime': 'createdDateTime' }[orderBy || 'name'] || 'name'} ${descending ? 'desc' : 'asc'}`,
                            pageSize: pageSize || 50,
                            pageNumber: pageNumber
                        });
                        result = {
                            operation: 'paginated_list',
                            folder: safeFolderPath || 'Root',
                            pageNumber: pageResults.pageNumber,
                            itemCount: pageResults.itemCount,
                            hasMore: pageResults.hasMore,
                            files: pageResults.items.map((item) => formatFileResult(item))
                        };
                        break;
                    }
                    catch (error) {
                        logger.warn(`Pagination failed, falling back to standard list: ${error.message}`);
                        // Continue with standard listing
                    }
                }
                // Standard list operation
                let listPath;
                // Handle empty string and normalize folder paths
                const normalizedFolderPath = safeFolderPath?.trim();
                if (normalizedFolderPath && normalizedFolderPath !== '') {
                    // Ensure proper path formatting
                    const cleanPath = normalizedFolderPath.replace(/^\/+|\/+$/g, ''); // Remove leading/trailing slashes
                    // Special handling for "Documents" which might be the default document library
                    if (cleanPath.toLowerCase() === 'documents' || cleanPath.toLowerCase() === 'shared documents') {
                        // Try to access the default document library first
                        listPath = `/sites/${site.id}/drive/root/children`;
                        logger.info(`Accessing default document library (Documents)`);
                    }
                    else {
                        listPath = `/sites/${site.id}/drive/root:/${encodeDrivePath(cleanPath)}:/children`;
                        logger.info(`Listing files in folder: ${cleanPath}`);
                    }
                }
                else {
                    // Root folder
                    listPath = `/sites/${site.id}/drive/root/children`;
                    logger.info(`Listing files in root folder`);
                }
                // Smart pagination: default to 10 items to avoid overwhelming context
                const itemsPerPage = maxResults || 10; // Default to 10 items instead of 50
                const effectiveLimit = Math.min(itemsPerPage, 999);
                // Map schema orderBy values to Graph API field names
                const orderByMap = {
                    'name': 'name',
                    'modified': 'lastModifiedDateTime',
                    'size': 'size',
                    'createdDateTime': 'createdDateTime'
                };
                const graphOrderBy = orderByMap[orderBy || 'name'] || 'name';
                let request = graphClient.api(listPath)
                    .top(effectiveLimit)
                    .select(DRIVE_ITEM_LIST_SELECT)
                    .orderby(`${graphOrderBy} ${descending ? 'desc' : 'asc'}`);
                // Apply filters
                const filter = buildSearchFilter();
                if (filter) {
                    request = request.filter(filter);
                }
                let response;
                try {
                    response = await withTimeout(throttledRetry(() => request.get()), 30000, // 30 second timeout
                    'List operation timed out after 30 seconds');
                }
                catch (error) {
                    logger.error(`Failed to list files in path: ${listPath}`, error);
                    // Check for specific error types
                    if (error.statusCode === 404 || error.message?.includes('resource could not be found')) {
                        // Special handling for Documents folder
                        if (normalizedFolderPath && (normalizedFolderPath.toLowerCase() === 'documents' || normalizedFolderPath.toLowerCase().startsWith('documents/'))) {
                            logger.info('Documents folder not found in default drive, checking for separate document library');
                            try {
                                // Get all drives for the site
                                const drivesResponse = await graphClient.api(`/sites/${site.id}/drives`)
                                    .select('id,name,driveType')
                                    .get();
                                // Find the Documents library
                                const documentsLibrary = drivesResponse.value.find((drive) => drive.name?.toLowerCase() === 'documents' ||
                                    drive.name?.toLowerCase() === 'shared documents' ||
                                    drive.driveType === 'documentLibrary');
                                if (documentsLibrary) {
                                    // Use the specific documents library
                                    const remainingPath = normalizedFolderPath.toLowerCase().startsWith('documents/')
                                        ? normalizedFolderPath.substring(10) // Remove "documents/" prefix
                                        : '';
                                    const documentsPath = remainingPath
                                        ? `/sites/${site.id}/drives/${documentsLibrary.id}/root:/${encodeDrivePath(remainingPath)}:/children`
                                        : `/sites/${site.id}/drives/${documentsLibrary.id}/root/children`;
                                    response = await graphClient.api(documentsPath)
                                        .top(Math.min(maxResults || 50, 999))
                                        .select(DRIVE_ITEM_LIST_SELECT)
                                        .orderby(`${{ 'name': 'name', 'modified': 'lastModifiedDateTime', 'size': 'size', 'createdDateTime': 'createdDateTime' }[orderBy || 'name'] || 'name'} ${descending ? 'desc' : 'asc'}`)
                                        .get();
                                    logger.info(`Successfully accessed Documents library: ${documentsLibrary.name}`);
                                }
                                else {
                                    throw new Error(`Documents folder not found. Available libraries: ${drivesResponse.value.map((d) => d.name).join(', ')}`);
                                }
                            }
                            catch (driveError) {
                                logger.error('Failed to access Documents library', driveError);
                                // Try default document library as last resort
                                try {
                                    const defaultPath = `/sites/${site.id}/drive/root/children`;
                                    response = await graphClient.api(defaultPath)
                                        .top(Math.min(maxResults || 50, 999))
                                        .select(DRIVE_ITEM_LIST_SELECT)
                                        .orderby(`${{ 'name': 'name', 'modified': 'lastModifiedDateTime', 'size': 'size', 'createdDateTime': 'createdDateTime' }[orderBy || 'name'] || 'name'} ${descending ? 'desc' : 'asc'}`)
                                        .get();
                                    logger.info('Successfully listed files from default document library');
                                }
                                catch (fallbackError) {
                                    throw new Error(`Could not access folder '${safeFolderPath || 'root'}'. The folder may not exist or you may not have permission. Original error: ${error.message}`);
                                }
                            }
                        }
                        else {
                            // For other folders, just try the default library
                            logger.info('Folder not found, trying default document library');
                            try {
                                const defaultPath = `/sites/${site.id}/drive/root/children`;
                                response = await graphClient.api(defaultPath)
                                    .top(effectiveLimit)
                                    .select(DRIVE_ITEM_LIST_SELECT)
                                    .orderby(`${{ 'name': 'name', 'modified': 'lastModifiedDateTime', 'size': 'size', 'createdDateTime': 'createdDateTime' }[orderBy || 'name'] || 'name'} ${descending ? 'desc' : 'asc'}`)
                                    .get();
                                logger.info('Successfully listed files from default document library');
                            }
                            catch (fallbackError) {
                                throw new Error(`Could not access folder '${safeFolderPath || 'root'}'. The folder may not exist or you may not have permission. Original error: ${error.message}`);
                            }
                        }
                    }
                    else {
                        throw error;
                    }
                }
                // If includeSubfolders is true, recursively get files from subfolders (with limits)
                let allFiles = response.value;
                if (includeSubfolders) {
                    const folders = response.value.filter((item) => item.folder);
                    // Limit subfolder recursion to prevent context overflow
                    const maxSubfolders = 5;
                    const foldersToProcess = folders.slice(0, maxSubfolders);
                    if (folders.length > maxSubfolders) {
                        logger.info(`Limiting subfolder processing to ${maxSubfolders} folders out of ${folders.length} to prevent context overflow`);
                    }
                    for (const folder of foldersToProcess) {
                        const subPath = safeFolderPath ? `${safeFolderPath}/${folder.name}` : folder.name;
                        const subRequest = graphClient.api(`/sites/${site.id}/drive/root:/${encodeDrivePath(subPath)}:/children`)
                            .top(effectiveLimit)
                            .select(DRIVE_ITEM_LIST_SELECT);
                        const subResponse = await subRequest.get().catch(() => ({ value: [] }));
                        allFiles = allFiles.concat(subResponse.value.slice(0, 5)); // Limit items from each subfolder
                    }
                }
                // Check if there are more items available
                const hasMoreItems = response['@odata.nextLink'] ? true : false;
                // Create a continuation token if there are more items
                let continuationInfo = null;
                if (hasMoreItems) {
                    continuationInfo = {
                        message: `Showing ${allFiles.length} items. More items are available.`,
                        nextLink: response['@odata.nextLink'],
                        suggestion: "To fetch more items, use the 'continue' operation or increase maxResults parameter.",
                        warningIfLarge: allFiles.length > 50 ? "Consider using smaller batches to avoid overwhelming the context window." : undefined
                    };
                }
                result = {
                    folder: safeFolderPath || 'Root',
                    itemsReturned: allFiles.length,
                    hasMore: hasMoreItems,
                    files: allFiles.map((item) => formatFileResult(item)),
                    ...(continuationInfo && { continuation: continuationInfo })
                };
                // Add summary if many items
                if (allFiles.length > 20) {
                    const fileCount = allFiles.filter((item) => item.file).length;
                    const folderCount = allFiles.filter((item) => item.folder).length;
                    result.summary = {
                        totalReturned: allFiles.length,
                        files: fileCount,
                        folders: folderCount,
                        note: "Use filters (fileType, modifiedAfter, etc.) to narrow results and avoid context overflow."
                    };
                }
                break;
            }
            case 'recent': {
                // Get recently modified files
                const daysAgo = daysBack || 7;
                const dateFilter = new Date();
                dateFilter.setDate(dateFilter.getDate() - daysAgo);
                let request = graphClient.api(`/sites/${site.id}/drive/root/children`)
                    .top(Math.min(maxResults || 50, 999))
                    .select(DRIVE_ITEM_LIST_SELECT)
                    .filter(`lastModifiedDateTime ge ${dateFilter.toISOString()} and file ne null`)
                    .orderby('lastModifiedDateTime desc');
                const response = await request.get();
                result = {
                    period: `Last ${daysAgo} days`,
                    totalFiles: response.value.length,
                    files: response.value.map((item) => formatFileResult(item))
                };
                break;
            }
            case 'by_type': {
                if (!fileType) {
                    throw new Error("by_type operation requires fileType parameter");
                }
                const filter = buildSearchFilter();
                let request = graphClient.api(`/sites/${site.id}/drive/root/children`)
                    .top(Math.min(maxResults || 50, 999))
                    .select(DRIVE_ITEM_LIST_SELECT)
                    .orderby(`${{ 'name': 'name', 'modified': 'lastModifiedDateTime', 'size': 'size', 'createdDateTime': 'createdDateTime' }[orderBy || 'name'] || 'name'} ${descending ? 'desc' : 'asc'}`);
                if (filter) {
                    request = request.filter(filter);
                }
                const response = await request.get();
                result = {
                    fileType: fileType,
                    totalFiles: response.value.length,
                    files: response.value.map((item) => formatFileResult(item))
                };
                break;
            }
            case 'large_files': {
                // Find files larger than 10MB by default
                const sizeThreshold = minSize || 10485760; // 10MB in bytes
                let request = graphClient.api(`/sites/${site.id}/drive/root/children`)
                    .top(Math.min(maxResults || 50, 999))
                    .select(DRIVE_ITEM_LIST_SELECT)
                    .filter(`size ge ${sizeThreshold} and file ne null`)
                    .orderby('size desc');
                const response = await request.get();
                result = {
                    sizeThreshold: formatFileSize(sizeThreshold),
                    totalFiles: response.value.length,
                    totalSize: formatFileSize(response.value.reduce((sum, item) => sum + (item.size || 0), 0)),
                    files: response.value.map((item) => formatFileResult(item))
                };
                break;
            }
            case 'shared': {
                // Get files that are shared
                let request = graphClient.api(`/sites/${site.id}/drive/root/children`)
                    .top(Math.min(maxResults || 50, 999))
                    .select(`${DRIVE_ITEM_LIST_SELECT},permissions`)
                    .filter('shared ne null and file ne null')
                    .orderby('lastModifiedDateTime desc')
                    .expand('permissions');
                const response = await request.get();
                result = {
                    totalSharedFiles: response.value.length,
                    files: response.value.map((item) => {
                        const fileInfo = formatFileResult(item);
                        if (item.permissions) {
                            fileInfo.sharedWith = item.permissions.map((p) => ({
                                type: p.grantedTo ? 'user' : 'link',
                                user: p.grantedTo?.user?.displayName || p.grantedTo?.user?.email,
                                permission: p.roles?.join(', '),
                                hasPassword: p.hasPassword,
                                link: p.link?.webUrl
                            }));
                        }
                        return fileInfo;
                    })
                };
                break;
            }
            case 'list_folders': {
                // List folder structure
                let listPath = `/sites/${site.id}/drive/root/children`;
                if (encodedFolderPath) {
                    listPath = `/sites/${site.id}/drive/root:/${encodedFolderPath}:/children`;
                }
                let request = graphClient.api(listPath)
                    .select('id,name,size,createdDateTime,lastModifiedDateTime,folder,parentReference')
                    .filter('folder ne null')
                    .orderby('name asc');
                const response = await request.get();
                result = {
                    currentPath: safeFolderPath || 'Root',
                    totalFolders: response.value.length,
                    folders: response.value.map((item) => ({
                        id: item.id,
                        name: item.name,
                        path: item.parentReference?.path?.replace('/drive/root:', '') || '/',
                        childCount: item.folder?.childCount || 0,
                        created: item.createdDateTime,
                        modified: item.lastModifiedDateTime
                    }))
                };
                break;
            }
            case 'get_metadata': {
                if (!fileId) {
                    throw new Error("get_metadata operation requires fileId parameter");
                }
                const response = await graphClient
                    .api(`/sites/${site.id}/drive/items/${fileId}`)
                    .select(DRIVE_ITEM_LIST_SELECT)
                    .expand('permissions')
                    .get();
                result = {
                    file: formatFileResult(response),
                    permissions: response.permissions?.map((p) => ({
                        id: p.id,
                        type: p.grantedTo ? 'user' : p.link ? 'link' : 'inherited',
                        user: p.grantedTo?.user?.displayName || p.grantedTo?.user?.email,
                        roles: p.roles,
                        inheritedFrom: p.inheritedFrom?.path
                    }))
                };
                break;
            }
            case 'get_content': {
                // bblg fork 0.1.4: return the bytes (base64/text, size-capped) or save them to disk.
                // The pre-authenticated download URL is no longer returned.
                let itemPath;
                if (fileId) {
                    itemPath = `/sites/${site.id}/drive/items/${fileId}`;
                }
                else if (params.filePath) {
                    itemPath = `/sites/${site.id}/drive/root:/${encodeDrivePath(sanitizePath(params.filePath))}:`;
                }
                else {
                    throw new Error("get_content operation requires fileId or filePath parameter");
                }
                result = await throttledRetry(() => downloadDriveItem(graphClient, {
                    itemPath,
                    saveToPath: params.saveToPath,
                    overwrite: params.overwrite,
                    encoding: params.downloadEncoding ?? 'auto'
                }));
                break;
            }
            case 'create_folder': {
                const name = folderName;
                if (!name) {
                    throw new Error("folderName is required for create_folder operation");
                }
                const parentPath = encodedFolderPath || '';
                const endpoint = parentPath
                    ? `/sites/${site.id}/drive/root:/${parentPath}:/children`
                    : `/sites/${site.id}/drive/root/children`;
                // A create may have been committed before a 5xx or dropped connection was reported;
                // retrying it would duplicate the folder (or surface a spurious 409).
                const createResult = await throttledRetry(() => graphClient.api(endpoint).post({
                    name: name,
                    folder: {},
                    "@microsoft.graph.conflictBehavior": "fail"
                }), { idempotent: false });
                result = {
                    message: `Folder '${name}' created successfully.`,
                    folder: createResult
                };
                break;
            }
            case 'delete': {
                if (!fileId) {
                    throw new Error("fileId is required for delete operation");
                }
                // A 404 on a retry means an earlier attempt already deleted the item.
                await throttledRetry(() => graphClient.api(`/sites/${site.id}/drive/items/${fileId}`).delete(), { notFoundAfterRetryIsSuccess: true });
                // Invalidate cache after delete
                siteCache.clear();
                result = {
                    message: `Item '${fileId}' deleted successfully.`
                };
                logger.audit('FILE_DELETED', {
                    action: 'DELETE',
                    targetResource: `file:${fileId}`,
                    result: 'SUCCESS',
                    metadata: { siteName, fileId }
                });
                break;
            }
            case 'update_content': {
                if (!fileId || content === undefined) {
                    throw new Error("fileId and content are required for update_content operation");
                }
                const bytes = decodeContent(content, contentEncoding ?? 'text');
                const maxUploadBytes = readPositiveInt('MAX_FILE_UPLOAD_SIZE', 104857600); // Default 100MB
                const replaced = await replaceFileContent(graphClient, {
                    siteId: site.id,
                    fileId,
                    content: bytes,
                    maxBytes: maxUploadBytes
                });
                result = {
                    message: `File content replaced (${replaced.bytes} bytes, ${replaced.method} upload). SharePoint keeps the previous version if versioning is enabled.`,
                    item: replaced.item
                };
                logger.audit('FILE_CONTENT_UPDATED', {
                    action: 'UPDATE_CONTENT',
                    targetResource: `file:${fileId}`,
                    result: 'SUCCESS',
                    metadata: { siteName, fileId, bytes: replaced.bytes, method: replaced.method }
                });
                break;
            }
            case 'rename': {
                if (!fileId || !newName) {
                    throw new Error("fileId and newName are required for rename operation");
                }
                const renameResult = await throttledRetry(() => graphClient.api(`/sites/${site.id}/drive/items/${fileId}`).patch({
                    name: newName
                }));
                result = {
                    message: `Item renamed to '${newName}' successfully.`,
                    item: renameResult
                };
                logger.audit('FILE_RENAMED', {
                    action: 'RENAME',
                    targetResource: `file:${fileId}`,
                    result: 'SUCCESS',
                    metadata: { siteName, fileId, newName }
                });
                break;
            }
            case 'copy': {
                if (!fileId) {
                    throw new Error("fileId is required for copy operation");
                }
                const copyBody = {};
                if (newName) {
                    copyBody.name = newName;
                }
                if (destinationPath) {
                    const destPath = sanitizePath(destinationPath);
                    copyBody.parentReference = {
                        path: `/drives/${site.id}/root:/${destPath}`
                    };
                }
                // Copy is an asynchronous server-side job: a retry after a lost response starts a second copy.
                const copyResult = await throttledRetry(() => graphClient.api(`/sites/${site.id}/drive/items/${fileId}/copy`).post(copyBody), { idempotent: false });
                result = {
                    message: `Copy operation initiated.`,
                    item: copyResult
                };
                logger.audit('FILE_COPIED', {
                    action: 'COPY',
                    targetResource: `file:${fileId}`,
                    result: 'SUCCESS',
                    metadata: { siteName, fileId, destinationPath: destinationPath || 'same location', newName: newName || 'same name' }
                });
                break;
            }
            case 'move': {
                if (!fileId || !destinationPath) {
                    throw new Error("fileId and destinationPath are required for move operation");
                }
                const destPath = sanitizePath(destinationPath);
                const moveBody = {
                    parentReference: {
                        path: `/drives/${site.id}/root:/${destPath}`
                    }
                };
                if (newName) {
                    moveBody.name = newName;
                }
                const moveResult = await throttledRetry(() => graphClient.api(`/sites/${site.id}/drive/items/${fileId}`).patch(moveBody));
                // Invalidate cache after move
                siteCache.clear();
                result = {
                    message: `Item moved to '${destinationPath}' successfully.`,
                    item: moveResult
                };
                logger.audit('FILE_MOVED', {
                    action: 'MOVE',
                    targetResource: `file:${fileId}`,
                    result: 'SUCCESS',
                    metadata: { siteName, fileId, destinationPath }
                });
                break;
            }
            default:
                throw new Error(`Unknown operation: ${operation}`);
        }
        // Add audit logging for sensitive operations
        if (['get_content', 'get_metadata'].includes(operation)) {
            logger.audit('SHAREPOINT_FILE_ACCESS', {
                action: operation.toUpperCase(),
                targetResource: `site:${site.displayName}`,
                result: 'SUCCESS',
                metadata: {
                    siteName,
                    operation,
                    fileId
                }
            });
        }
        return {
            content: [{
                    type: "text",
                    text: JSON.stringify(result, null, 2)
                }]
        };
    }
    catch (error) {
        logger.error(`Error in sharepoint-site-files tool:`, error);
        return {
            content: [{
                    type: "text",
                    text: JSON.stringify({
                        error: error.message,
                        operation: params.operation,
                        site: params.siteName
                    }, null, 2)
                }],
            isError: true
        };
    }
}
// SharePoint Site Discovery Tool
server.tool("sharepoint-site-discovery", "Discover and list SharePoint sites accessible to the authenticated user. Supports searching, filtering by site type, and retrieving user's followed sites.", sharePointSiteDiscoverySchema, async (params) => {
    try {
        await policyGuard.enforce({ tool: 'sharepoint-site-discovery', verb: 'read', resource: '/sites' });
        // Check and auto-initialize Graph client if needed
        if (!graphClient && authManager) {
            if (authManager.getAuthMode() === AuthMode.ClientProvidedToken) {
                const reinitializedFromCache = await authManager.tryInitializeFromCache();
                if (reinitializedFromCache) {
                    const authProvider = authManager.getGraphAuthProvider();
                    graphClient = createGraphClient(authProvider);
                    logger.info("Graph client auto-initialized from cached token for Site Discovery");
                }
            }
        }
        if (!graphClient) {
            if (authManager?.getAuthMode() === AuthMode.ClientProvidedToken) {
                throw new Error("Authentication not initialized. Please use the 'set-access-token' tool first to provide an access token.");
            }
            else {
                throw new Error("Graph client not initialized. Check authentication configuration.");
            }
        }
        // Permission validation
        if (authManager) {
            const tokenStatus = await authManager.getTokenStatus();
            const scopes = tokenStatus.scopes || [];
            const permissionCheck = PermissionValidator.validateScopes('/sites', 'get', scopes);
            if (!permissionCheck.allowed) {
                logger.warn('Permission denied for site discovery', {
                    reason: permissionCheck.reason,
                    requiredScopes: permissionCheck.requiredScopes
                });
                throw new Error(`Permission denied: ${permissionCheck.reason}. Required scopes: ${permissionCheck.requiredScopes?.join(', ')}`);
            }
        }
        const { operation, searchQuery, maxResults, // No default - let it be undefined to fetch all
        orderBy = "displayName", includeDetails = false, includeSubsites = false, summaryMode = true, pageSize = 20, continuationToken, siteIds } = params;
        logger.info(`SharePoint site discovery: operation=${operation}, searchQuery=${searchQuery}, maxResults=${maxResults || 'unlimited'}`);
        let result = {};
        // Helper function to create summary for large result sets
        function createSummary(sites, totalCount) {
            const summary = {
                totalCount: totalCount,
                returnedCount: sites.length,
                summaryMode: true
            };
            // Group by type if we have many sites
            if (sites.length > 50) {
                const groups = {};
                sites.forEach(site => {
                    const type = site.siteType || (site.isPersonalSite ? 'Personal' : 'Standard');
                    if (!groups[type])
                        groups[type] = [];
                    groups[type].push(site);
                });
                summary.sitesByType = {};
                for (const [type, sitesInGroup] of Object.entries(groups)) {
                    summary.sitesByType[type] = {
                        count: sitesInGroup.length,
                        examples: sitesInGroup.slice(0, 3).map(s => ({
                            name: s.displayName,
                            url: s.url,
                            id: s.id
                        }))
                    };
                }
            }
            // Sample strategy for very large result sets
            if (sites.length > 100) {
                const sampled = [
                    ...sites.slice(0, 10), // First 10
                    ...sites.slice(Math.floor(sites.length / 2) - 5, Math.floor(sites.length / 2) + 5), // Middle 10
                    ...sites.slice(-10) // Last 10
                ];
                summary.sample = sampled;
                summary.message = `Showing sample of 30 sites from ${totalCount} total. Use 'continue' operation or refine your search.`;
            }
            else {
                summary.sites = sites;
            }
            return summary;
        }
        // Continuation tokens: one bounded, expiring cache entry per result set (F11).
        function generateContinuationToken(data, position, query) {
            return paginationCache.issue(data, position, query);
        }
        // Every fetch-every-page loop below stops at the server caps rather than growing unbounded.
        const fetchAllCapReached = (items, pages) => items.length >= MAX_FETCH_ALL_ITEMS || pages >= MAX_FETCH_ALL_PAGES;
        const fetchAllNote = (items, pages) => `Stopped after ${items.length} sites across ${pages} pages (server caps: MAX_FETCH_ALL_ITEMS=${MAX_FETCH_ALL_ITEMS}, MAX_FETCH_ALL_PAGES=${MAX_FETCH_ALL_PAGES}). Use maxResults or a narrower search.`;
        switch (operation) {
            case 'list_all': {
                // List all sites accessible to the user - fetch ALL sites with pagination
                const allSites = [];
                let hasMore = true;
                let nextLink = null;
                const pageSize = 100; // Optimal page size for Graph API
                let pageCount = 0;
                let listAllTruncated = false;
                // Build initial request
                let request = graphClient.api('/sites')
                    .top(pageSize)
                    .select('id,name,displayName,webUrl,description,createdDateTime,lastModifiedDateTime,root');
                // Add ordering
                if (orderBy) {
                    request = request.orderby(`${orderBy} asc`);
                }
                // Paginate through all sites
                while (hasMore) {
                    let response;
                    pageCount++;
                    if (nextLink) {
                        // Use the nextLink for subsequent pages
                        logger.debug(`Fetching page ${pageCount} using nextLink: ${nextLink}`);
                        response = await graphClient.api(validateGraphNextLink(nextLink)).get();
                    }
                    else {
                        // First page
                        logger.debug(`Fetching page ${pageCount} (initial request)`);
                        response = await request.get();
                    }
                    if (response.value && response.value.length > 0) {
                        allSites.push(...response.value);
                        logger.info(`Page ${pageCount}: fetched ${response.value.length} sites, total: ${allSites.length}`);
                        // Check if we've reached the optional maxResults limit
                        if (maxResults && allSites.length >= maxResults) {
                            // Trim to maxResults if specified
                            allSites.splice(maxResults);
                            logger.info(`Reached maxResults limit of ${maxResults}, stopping pagination`);
                            hasMore = false;
                        }
                        else if (response['@odata.nextLink'] && fetchAllCapReached(allSites, pageCount)) {
                            allSites.splice(MAX_FETCH_ALL_ITEMS);
                            listAllTruncated = true;
                            logger.warn(`list_all stopped at the fetch-all cap after ${pageCount} pages`);
                            hasMore = false;
                        }
                        else if (response['@odata.nextLink']) {
                            // Continue to next page
                            nextLink = response['@odata.nextLink'];
                            logger.debug(`More pages available, will fetch next`);
                        }
                        else {
                            // No more pages
                            logger.info(`No more pages available, total sites: ${allSites.length}`);
                            hasMore = false;
                        }
                    }
                    else {
                        logger.info(`Page ${pageCount}: no sites returned, stopping pagination`);
                        hasMore = false;
                    }
                }
                // Apply smart data handling based on result size
                if (summaryMode && allSites.length > 50) {
                    logger.info(`Large result set (${allSites.length} sites), using summary mode`);
                    // Format only a subset if we're in summary mode
                    const sitesToFormat = allSites.length > 100 ?
                        [...allSites.slice(0, 10), ...allSites.slice(-10)] :
                        allSites.slice(0, 50);
                    const formattedSites = sitesToFormat.map((site) => formatSiteInfo(site));
                    // Don't fetch details in summary mode for large datasets
                    if (includeDetails && allSites.length <= 100) {
                        // Only get details for the sample
                        for (const site of formattedSites.slice(0, 5)) {
                            try {
                                const details = await getSiteDetails(site.id);
                                Object.assign(site, details);
                            }
                            catch (error) {
                                logger.debug(`Could not get details for site ${site.id}`, error);
                            }
                        }
                    }
                    result = createSummary(formattedSites, allSites.length);
                    result.operation = 'list_all';
                    if (listAllTruncated) {
                        result.truncated = true;
                        result.note = fetchAllNote(allSites, pageCount);
                    }
                    // Generate continuation token if there are more results
                    if (allSites.length > pageSize) {
                        const token = generateContinuationToken(allSites, pageSize, { operation: 'list_all', orderBy });
                        result.continuationToken = token;
                        result.hasMore = true;
                        result.nextPage = `Use 'continue' operation with token: ${token}`;
                    }
                }
                else {
                    // Standard processing for smaller result sets
                    const sites = await Promise.all(allSites.map(async (site) => {
                        const formatted = formatSiteInfo(site);
                        // Optionally get additional details
                        if (includeDetails) {
                            try {
                                const details = await getSiteDetails(site.id);
                                Object.assign(formatted, details);
                            }
                            catch (error) {
                                logger.debug(`Could not get details for site ${site.id}`, error);
                            }
                        }
                        return formatted;
                    }));
                    result = {
                        operation: 'list_all',
                        totalSites: sites.length,
                        sites: sites,
                        ...(listAllTruncated && { truncated: true, note: fetchAllNote(allSites, pageCount) })
                    };
                }
                break;
            }
            case 'search': {
                if (!searchQuery) {
                    throw new Error("Search operation requires searchQuery parameter");
                }
                // Search for sites with pagination
                const allSites = [];
                let hasMore = true;
                let nextLink = null;
                const pageSize = 100;
                let searchPages = 0;
                let searchTruncated = false;
                // Wildcard search: fall back to list_all behavior since Graph API
                // doesn't support wildcards in /sites search
                const isWildcard = searchQuery.trim() === '*';
                // Build initial search request
                let request = graphClient.api('/sites')
                    .top(pageSize)
                    .select('id,name,displayName,webUrl,description,createdDateTime,lastModifiedDateTime');
                if (!isWildcard) {
                    request = request.search(`"${escapeKQL(searchQuery)}"`);
                }
                // Paginate through search results
                while (hasMore) {
                    let response;
                    searchPages++;
                    if (nextLink) {
                        response = await graphClient.api(validateGraphNextLink(nextLink)).get();
                    }
                    else {
                        response = await request.get();
                    }
                    if (response.value && response.value.length > 0) {
                        allSites.push(...response.value);
                        // Check if we've reached the optional maxResults limit
                        if (maxResults && allSites.length >= maxResults) {
                            allSites.splice(maxResults);
                            hasMore = false;
                        }
                        else if (response['@odata.nextLink'] && fetchAllCapReached(allSites, searchPages)) {
                            allSites.splice(MAX_FETCH_ALL_ITEMS);
                            searchTruncated = true;
                            hasMore = false;
                        }
                        else if (response['@odata.nextLink']) {
                            nextLink = response['@odata.nextLink'];
                        }
                        else {
                            hasMore = false;
                        }
                    }
                    else {
                        hasMore = false;
                    }
                }
                const sites = allSites.map((site) => formatSiteInfo(site));
                result = {
                    operation: 'search',
                    searchQuery: searchQuery,
                    totalResults: sites.length,
                    sites: sites,
                    ...(searchTruncated && { truncated: true, note: fetchAllNote(allSites, searchPages) })
                };
                break;
            }
            case 'my_sites': {
                // Get user's followed sites
                try {
                    // Fetch all followed sites with pagination
                    const allSites = [];
                    let nextLink = null;
                    let hasMore = true;
                    const pageSize = 100;
                    let mySitesPages = 0;
                    let mySitesTruncated = false;
                    while (hasMore) {
                        let response;
                        mySitesPages++;
                        if (nextLink) {
                            response = await graphClient.api(validateGraphNextLink(nextLink)).get();
                        }
                        else {
                            response = await graphClient
                                .api('/me/followedSites')
                                .top(pageSize)
                                .select('id,name,displayName,webUrl,description,createdDateTime')
                                .get();
                        }
                        if (response.value && response.value.length > 0) {
                            allSites.push(...response.value);
                            if (maxResults && allSites.length >= maxResults) {
                                allSites.splice(maxResults);
                                hasMore = false;
                            }
                            else if (response['@odata.nextLink'] && fetchAllCapReached(allSites, mySitesPages)) {
                                allSites.splice(MAX_FETCH_ALL_ITEMS);
                                mySitesTruncated = true;
                                hasMore = false;
                            }
                            else if (response['@odata.nextLink']) {
                                nextLink = response['@odata.nextLink'];
                            }
                            else {
                                hasMore = false;
                            }
                        }
                        else {
                            hasMore = false;
                        }
                    }
                    const sites = allSites.map((site) => formatSiteInfo(site));
                    result = {
                        operation: 'my_sites',
                        totalSites: sites.length,
                        sites: sites,
                        ...(mySitesTruncated && { truncated: true, note: fetchAllNote(allSites, mySitesPages) })
                    };
                }
                catch (error) {
                    // Fallback to recent sites if followed sites not available
                    logger.debug('Followed sites not available, trying recent sites', error);
                    try {
                        const recentSites = await graphClient
                            .api('/me/insights/used')
                            .filter("resourceReference/type eq 'microsoft.graph.site'")
                            .top(maxResults || 100)
                            .get();
                        const sites = recentSites.value
                            .filter((item) => item.resourceReference?.type === 'microsoft.graph.site')
                            .map((item) => ({
                            id: item.resourceReference?.id,
                            name: item.resourceVisualization?.title,
                            displayName: item.resourceVisualization?.title,
                            webUrl: item.resourceReference?.webUrl,
                            lastUsed: item.lastUsed?.lastAccessedDateTime,
                            containerType: item.resourceVisualization?.containerType
                        }));
                        result = {
                            operation: 'my_sites',
                            source: 'recent_activity',
                            totalSites: sites.length,
                            sites: sites
                        };
                    }
                    catch (fallbackError) {
                        throw new Error(`Could not retrieve user's sites: ${error.message}`);
                    }
                }
                break;
            }
            case 'hub_sites': {
                // List hub sites
                try {
                    // Hub sites require special permissions and might not be available
                    const hubSites = await graphClient
                        .api('/sites')
                        .filter("siteCollection/root ne null and isPersonalSite eq false")
                        .top(maxResults || 100)
                        .select('id,name,displayName,webUrl,description,createdDateTime,siteCollection')
                        .get();
                    const sites = hubSites.value
                        .filter((site) => site.siteCollection?.isHubSite)
                        .map((site) => ({
                        ...formatSiteInfo(site),
                        isHubSite: true,
                        hubSiteId: site.siteCollection?.hubSiteId
                    }));
                    result = {
                        operation: 'hub_sites',
                        totalSites: sites.length,
                        sites: sites
                    };
                }
                catch (error) {
                    logger.warn('Could not retrieve hub sites', error);
                    result = {
                        operation: 'hub_sites',
                        totalSites: 0,
                        sites: [],
                        note: 'Hub sites require special permissions. Listing regular sites instead.'
                    };
                }
                break;
            }
            case 'team_sites': {
                // List team sites (connected to Microsoft 365 groups)
                try {
                    // Get groups with SharePoint sites
                    const groups = await graphClient
                        .api('/groups')
                        .filter("groupTypes/any(c:c eq 'Unified') and resourceProvisioningOptions/Any(x:x eq 'Team')")
                        .top(maxResults || 100)
                        .select('id,displayName,description,createdDateTime,sites')
                        .expand('sites')
                        .get();
                    const sites = [];
                    for (const group of groups.value) {
                        try {
                            // Get the team site for this group
                            const site = await graphClient
                                .api(`/groups/${group.id}/sites/root`)
                                .select('id,name,displayName,webUrl,description,createdDateTime')
                                .get();
                            sites.push({
                                ...formatSiteInfo(site),
                                siteType: 'TeamSite',
                                groupId: group.id,
                                groupName: group.displayName
                            });
                        }
                        catch (error) {
                            logger.debug(`Could not get site for group ${group.id}`, error);
                        }
                    }
                    result = {
                        operation: 'team_sites',
                        totalSites: sites.length,
                        sites: sites
                    };
                }
                catch (error) {
                    // Fallback to filtering regular sites
                    const response = await graphClient
                        .api('/sites')
                        .top(maxResults || 100)
                        .select('id,name,displayName,webUrl,description,createdDateTime,siteCollection')
                        .get();
                    const sites = response.value
                        .filter((site) => !site.isPersonalSite)
                        .map((site) => ({
                        ...formatSiteInfo(site),
                        siteType: 'TeamSite'
                    }));
                    result = {
                        operation: 'team_sites',
                        totalSites: sites.length,
                        sites: sites
                    };
                }
                break;
            }
            case 'communication_sites': {
                // List communication sites
                const response = await graphClient
                    .api('/sites')
                    .filter("siteCollection/root ne null")
                    .top(maxResults || 100)
                    .select('id,name,displayName,webUrl,description,createdDateTime,siteCollection')
                    .get();
                const sites = response.value
                    .filter((site) => site.siteCollection &&
                    !site.isPersonalSite &&
                    !site.siteCollection?.isHubSite)
                    .map((site) => ({
                    ...formatSiteInfo(site),
                    siteType: 'CommunicationSite',
                    template: site.siteCollection?.template
                }));
                result = {
                    operation: 'communication_sites',
                    totalSites: sites.length,
                    sites: sites
                };
                break;
            }
            case 'continue': {
                // Continue from a previous paginated result
                if (!continuationToken) {
                    throw new Error("continue operation requires continuationToken parameter");
                }
                const cached = paginationCache.get(continuationToken);
                if (!cached) {
                    throw new Error("Invalid or expired continuation token. Please start a new search.");
                }
                const { data, position, query } = cached;
                const nextPosition = position + pageSize;
                const page = data.slice(position, nextPosition);
                // Format the page of results
                const formattedPage = page.map((site) => formatSiteInfo(site));
                result = {
                    operation: 'continue',
                    pageNumber: Math.floor(position / pageSize) + 2, // Page 2, 3, etc.
                    itemsInPage: formattedPage.length,
                    totalItems: data.length,
                    sites: formattedPage
                };
                // Rotate the token in place if there are more results: the result set stays cached once.
                if (nextPosition < data.length) {
                    const newToken = paginationCache.advance(continuationToken, nextPosition) ?? generateContinuationToken(data, nextPosition, query);
                    result.continuationToken = newToken;
                    result.hasMore = true;
                    result.remainingItems = data.length - nextPosition;
                }
                else {
                    result.hasMore = false;
                    paginationCache.delete(continuationToken); // Clean up
                }
                break;
            }
            case 'get_details': {
                // Get detailed information for specific sites
                if (!siteIds || siteIds.length === 0) {
                    throw new Error("get_details operation requires siteIds parameter");
                }
                const detailedSites = await Promise.all(siteIds.slice(0, 10).map(async (siteId) => {
                    try {
                        if (!graphClient) {
                            throw new Error("Graph client not initialized");
                        }
                        // Get basic site info
                        const site = await graphClient.api(`/sites/${siteId}`)
                            .select('id,name,displayName,webUrl,description,createdDateTime,lastModifiedDateTime,root')
                            .get();
                        const formatted = formatSiteInfo(site);
                        // Always get details for this operation
                        try {
                            const details = await getSiteDetails(siteId);
                            Object.assign(formatted, details);
                        }
                        catch (error) {
                            logger.debug(`Could not get additional details for site ${siteId}`, error);
                        }
                        // Get subsites if requested
                        if (includeSubsites && graphClient) {
                            try {
                                const subsites = await graphClient
                                    .api(`/sites/${siteId}/sites`)
                                    .top(5)
                                    .select('id,name,displayName,webUrl')
                                    .get();
                                if (subsites.value && subsites.value.length > 0) {
                                    formatted.subsites = subsites.value.map((subsite) => ({
                                        id: subsite.id,
                                        name: subsite.name,
                                        displayName: subsite.displayName,
                                        url: subsite.webUrl
                                    }));
                                }
                            }
                            catch (error) {
                                logger.debug(`Could not get subsites for ${siteId}`, error);
                            }
                        }
                        return formatted;
                    }
                    catch (error) {
                        logger.error(`Failed to get details for site ${siteId}`, error);
                        return {
                            id: siteId,
                            error: error.message
                        };
                    }
                }));
                result = {
                    operation: 'get_details',
                    requestedCount: siteIds.length,
                    returnedCount: detailedSites.length,
                    sites: detailedSites
                };
                if (siteIds.length > 10) {
                    result.note = `Limited to 10 sites per request. ${siteIds.length - 10} sites were not processed.`;
                }
                break;
            }
            default:
                throw new Error(`Unknown operation: ${operation}`);
        }
        // Helper function to format site information
        function formatSiteInfo(site) {
            return {
                id: site.id,
                name: site.name,
                displayName: site.displayName || site.name,
                url: site.webUrl,
                description: site.description,
                createdDateTime: site.createdDateTime,
                lastModifiedDateTime: site.lastModifiedDateTime,
                // Extract tenant and site collection info if available
                tenantId: site.sharepointIds?.tenantId,
                siteId: site.sharepointIds?.siteId,
                webId: site.sharepointIds?.webId,
                // Site collection properties if available
                isRootSite: site.root ? true : false,
                isPersonalSite: site.isPersonalSite || false
            };
        }
        // Helper function to get additional site details with batching
        async function getSiteDetails(siteId) {
            try {
                if (!graphClient) {
                    return {};
                }
                // Check cache first
                const cacheKey = `site-details:${siteId}`;
                const cached = siteCache.get(cacheKey);
                if (cached) {
                    return cached;
                }
                // Use batch request for better performance
                const batchRequests = [
                    { id: '1', method: 'GET', url: `/sites/${siteId}/drives?$top=5&$select=id,name,driveType,quota` },
                    { id: '2', method: 'GET', url: `/sites/${siteId}/lists?$top=5&$select=id,displayName` }
                ];
                const batchResults = await batchGraphRequests(graphClient, batchRequests);
                const drives = batchResults.get('1') || { value: [] };
                const lists = batchResults.get('2') || { value: [] };
                const details = {
                    documentLibraryCount: drives.value?.length || 0,
                    listCount: lists.value?.length || 0,
                    storageUsed: drives.value?.[0]?.quota?.used,
                    storageTotal: drives.value?.[0]?.quota?.total
                };
                // Cache the result
                siteCache.set(cacheKey, details);
                return details;
            }
            catch (error) {
                return {};
            }
        }
        // Add subsites if requested
        if (includeSubsites && result.sites && graphClient) {
            for (const site of result.sites) {
                try {
                    const subsites = await graphClient
                        .api(`/sites/${site.id}/sites`)
                        .top(10)
                        .select('id,name,displayName,webUrl,description')
                        .get();
                    if (subsites.value && subsites.value.length > 0) {
                        site.subsites = subsites.value.map((subsite) => ({
                            id: subsite.id,
                            name: subsite.name,
                            displayName: subsite.displayName,
                            url: subsite.webUrl
                        }));
                        site.subsiteCount = subsites.value.length;
                    }
                }
                catch (error) {
                    logger.debug(`Could not get subsites for ${site.id}`, error);
                }
            }
        }
        // Audit logging
        logger.audit('SHAREPOINT_SITE_DISCOVERY', {
            action: operation.toUpperCase(),
            result: 'SUCCESS',
            metadata: {
                operation,
                searchQuery,
                resultCount: result.sites?.length || 0
            }
        });
        // Add security headers to response
        const response = {
            content: [{
                    type: "text",
                    text: JSON.stringify(result, null, 2)
                }]
        };
        return addSecurityHeaders(response);
    }
    catch (error) {
        logger.error(`Error in sharepoint-site-discovery tool:`, error);
        const errorResponse = {
            content: [{
                    type: "text",
                    text: JSON.stringify({
                        error: error.message,
                        operation: params.operation,
                        suggestion: "Try 'list_all' operation first to see available sites, or check your permissions."
                    }, null, 2)
                }],
            isError: true
        };
        return addSecurityHeaders(errorResponse);
    }
});
// File Parser Tool for documents (PDF, Word, Excel, etc.)
// bblg fork 0.1.4: generic download for SharePoint and OneDrive drive items.
server.tool("download-file", "Download a SharePoint or OneDrive file. Identify it by siteName + fileId/filePath, driveId + itemId/filePath, userId + filePath/itemId (a user's OneDrive), or shareUrl (a sharing link or file URL). Returns the content as base64 (or text) up to MAX_INLINE_DOWNLOAD_SIZE (default 10 MB), or writes it to saveToPath on the server's machine (up to MAX_FILE_DOWNLOAD_SIZE, default 100 MB). Never returns a download URL.", downloadFileSchema, async (params) => {
    try {
        const { siteName, driveId, userId, itemId, fileId, filePath, shareUrl, saveToPath, overwrite, encoding } = params;
        await policyGuard.enforce({ tool: 'download-file', verb: 'read', resource: siteName ? `site:${siteName}` : (driveId ? `drive:${driveId}` : (userId ? `user:${userId}` : 'share')) });
        if (!graphClient && authManager?.getAuthMode() === AuthMode.ClientProvidedToken) {
            if (await authManager.tryInitializeFromCache()) {
                graphClient = createGraphClient(authManager.getGraphAuthProvider());
            }
        }
        if (!graphClient) {
            throw new Error("Graph client not initialized. Check authentication configuration.");
        }
        const id = itemId || fileId;
        const encPath = filePath ? encodeDrivePath(sanitizePath(filePath)) : null;
        let base;
        let itemPath;
        if (shareUrl) {
            if (!/^https:\/\//i.test(shareUrl)) throw new Error("shareUrl must be an https URL");
            const token = 'u!' + Buffer.from(shareUrl, 'utf8').toString('base64').replace(/=+$/, '').replace(/\//g, '_').replace(/\+/g, '-');
            itemPath = `/shares/${token}/driveItem`;
        }
        else {
            if (driveId) {
                if (!/^[A-Za-z0-9!_-]{1,200}$/.test(driveId)) throw new Error("invalid driveId");
                base = `/drives/${driveId}`;
            }
            else if (userId) {
                if (!/^[^/?#\s\\]{1,200}$/.test(userId)) throw new Error("invalid userId");
                base = `/users/${encodeURIComponent(userId)}/drive`;
            }
            else if (siteName) {
                const site = await findSite(siteName, graphClient, siteCache);
                base = `/sites/${site.id}/drive`;
            }
            else {
                throw new Error("Provide shareUrl, or siteName/driveId/userId plus fileId/itemId or filePath");
            }
            if (id) itemPath = `${base}/items/${id}`;
            else if (encPath) itemPath = `${base}/root:/${encPath}:`;
            else throw new Error("Provide fileId/itemId or filePath");
        }
        const result = await throttledRetry(() => downloadDriveItem(graphClient, { itemPath, saveToPath, overwrite, encoding: encoding ?? 'auto' }));
        logger.audit('SHAREPOINT_FILE_ACCESS', { action: 'DOWNLOAD', targetResource: result.id, result: 'SUCCESS', metadata: { bytes: result.size, toDisk: !!saveToPath } });
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
    catch (error) {
        logger.error("Error in download-file tool:", error);
        return { content: [{ type: "text", text: JSON.stringify({ error: error.message }, null, 2) }], isError: true };
    }
});
server.tool("file-parser", "Parse and extract text from SharePoint documents including PDF, Word, Excel, PowerPoint, and other formats. Perfect for document summarization and content analysis.", fileParserSchema, async (params) => {
    try {
        await policyGuard.enforce({ tool: 'file-parser', verb: 'read', resource: `site:${params.siteName}` });
        // Check and auto-initialize Graph client if needed
        if (!graphClient && authManager) {
            if (authManager.getAuthMode() === AuthMode.ClientProvidedToken) {
                const reinitializedFromCache = await authManager.tryInitializeFromCache();
                if (reinitializedFromCache) {
                    const authProvider = authManager.getGraphAuthProvider();
                    graphClient = createGraphClient(authProvider);
                    logger.info("Graph client auto-initialized from cached token for File Parser");
                }
            }
        }
        if (!graphClient) {
            if (authManager?.getAuthMode() === AuthMode.ClientProvidedToken) {
                throw new Error("Authentication not initialized. Please use the 'set-access-token' tool first to provide an access token.");
            }
            else {
                throw new Error("Graph client not initialized. Check authentication configuration.");
            }
        }
        const { siteName, filePath, fileId, operation = "parse", includeMetadata = true } = params;
        // Validate that either filePath or fileId is provided
        if (!filePath && !fileId) {
            throw new Error("Either 'filePath' or 'fileId' parameter is required");
        }
        logger.info(`File parser operation: ${operation} on ${fileId ? `file ID: ${fileId}` : `file: ${filePath}`} in site: ${siteName}`);
        // Find the site first (using shared findSite from site-utils)
        const site = await findSite(siteName, graphClient, siteCache);
        logger.info(`Found SharePoint site for parsing: ${site.displayName} (${site.id})`);
        try {
            let metadataEndpoint;
            let contentEndpoint;
            let fileMetadata;
            if (fileId) {
                // Direct access using file ID
                logger.info(`Using direct file ID access: ${fileId}`);
                // Check if it's a full ID or needs site prefix
                if (fileId.startsWith('01')) {
                    // Looks like a drive item ID
                    metadataEndpoint = `/sites/${site.id}/drive/items/${fileId}`;
                    contentEndpoint = `/sites/${site.id}/drive/items/${fileId}/content`;
                }
                else {
                    // Might be a different format, try as-is
                    metadataEndpoint = `/drives/${site.id}/items/${fileId}`;
                    contentEndpoint = `/drives/${site.id}/items/${fileId}/content`;
                }
            }
            else if (filePath) {
                // Path-based access
                const normalizedPath = sanitizePath(filePath);
                // Check if the path looks like a file ID (common mistake)
                if (normalizedPath.match(/^01[A-Z0-9]{20,}$/)) {
                    logger.info(`Path appears to be a file ID, using direct access: ${normalizedPath}`);
                    metadataEndpoint = `/sites/${site.id}/drive/items/${normalizedPath}`;
                    contentEndpoint = `/sites/${site.id}/drive/items/${normalizedPath}/content`;
                }
                else {
                    // Standard path-based access
                    metadataEndpoint = `/sites/${site.id}/drive/root:/${encodeDrivePath(normalizedPath)}`;
                    contentEndpoint = `/sites/${site.id}/drive/root:/${encodeDrivePath(normalizedPath)}:/content`;
                }
            }
            else {
                throw new Error("No file identifier provided");
            }
            // Get file metadata first
            try {
                fileMetadata = await throttledRetry(() => graphClient.api(metadataEndpoint).get());
            }
            catch (metadataError) {
                if (metadataError.statusCode === 404) {
                    const identifier = fileId || filePath;
                    throw new Error(`File not found: '${identifier}'\n` +
                        `Tried endpoint: ${metadataEndpoint}\n\n` +
                        `Please verify:\n` +
                        `1. The file exists in site '${siteName}'\n` +
                        `2. You have permission to access it\n` +
                        `3. The path or ID is correct\n\n` +
                        `Valid formats:\n` +
                        `- File ID: '01B65XAEES6VTGM5KFC5AYMZJX4RXAEMNN'\n` +
                        `- Full path: '/Documents/folder/file.pdf'\n` +
                        `- Relative path: 'folder/file.pdf'`);
                }
                throw metadataError;
            }
            const filename = fileMetadata.name || (filePath ? filePath.split('/').pop() : 'unknown') || '';
            const mimeType = fileMetadata.file?.mimeType || '';
            // Security: Check file size before downloading to prevent OOM/DoS
            const maxFileSize = readPositiveInt('MAX_FILE_DOWNLOAD_SIZE', 104857600); // Default 100MB
            if (fileMetadata.size && fileMetadata.size > maxFileSize) {
                throw new Error(`File too large to download: ${fileMetadata.size} bytes (${(fileMetadata.size / 1024 / 1024).toFixed(1)}MB). ` +
                    `Maximum allowed size is ${(maxFileSize / 1024 / 1024).toFixed(1)}MB. ` +
                    `Set MAX_FILE_DOWNLOAD_SIZE environment variable to increase the limit.`);
            }
            logger.info(`Downloading file: ${filename} (${mimeType}, ${fileMetadata.size} bytes)`);
            // Use the microsoft-graph tool to download the file
            // This will handle the stream properly and return base64 encoded data
            // bblg fork 0.1.4: fetch through the item's download URL. Graph's /content redirect leaves
            // graph.microsoft.com and is refused by the origin-checked client, which broke file-parser.
            const downloadResponse = (await throttledRetry(() => downloadDriveItem(graphClient, {
                itemPath: metadataEndpoint, maxBytes: maxFileSize, raw: true
            }))).bytes;
            const response = downloadResponse;
            if (!response || response.length === 0) {
                throw new Error('File content is empty or could not be retrieved');
            }
            logger.info(`Downloaded ${response.length} bytes, parsing document...`);
            // Parse the document in a worker thread under PARSE_TIMEOUT_MS, so a pathological file
            // cannot stall the JSON-RPC thread.
            const parseResult = await DocumentParser.parseDocumentIsolated(response, filename, mimeType);
            let result = {};
            switch (operation) {
                case 'parse':
                    result = {
                        filename: filename,
                        filePath: filePath || fileId,
                        siteUrl: site.webUrl,
                        text: parseResult.text,
                        metadata: includeMetadata ? {
                            ...parseResult.metadata,
                            fileSize: fileMetadata.size,
                            lastModified: fileMetadata.lastModifiedDateTime,
                            createdBy: fileMetadata.createdBy?.user?.displayName,
                            mimeType: mimeType
                        } : undefined
                    };
                    break;
                case 'summarize':
                    // Provide a basic summary (first 1000 characters + key metadata)
                    const summary = parseResult.text.substring(0, 1000) +
                        (parseResult.text.length > 1000 ? '...' : '');
                    result = {
                        filename: filename,
                        filePath: filePath || fileId,
                        summary: summary,
                        totalLength: parseResult.text.length,
                        documentType: parseResult.metadata.format,
                        keyMetadata: {
                            pages: parseResult.metadata.pages,
                            sheets: parseResult.metadata.sheets?.length,
                            slides: parseResult.metadata.slides,
                            author: parseResult.metadata.author,
                            title: parseResult.metadata.title,
                            createdDate: parseResult.metadata.createdDate || fileMetadata.createdDateTime,
                            modifiedDate: parseResult.metadata.modifiedDate || fileMetadata.lastModifiedDateTime
                        }
                    };
                    break;
                case 'metadata':
                    result = {
                        filename: filename,
                        filePath: filePath || fileId,
                        metadata: {
                            ...parseResult.metadata,
                            sharePointMetadata: {
                                id: fileMetadata.id,
                                size: fileMetadata.size,
                                mimeType: mimeType,
                                webUrl: fileMetadata.webUrl,
                                createdDateTime: fileMetadata.createdDateTime,
                                lastModifiedDateTime: fileMetadata.lastModifiedDateTime,
                                createdBy: fileMetadata.createdBy?.user?.displayName,
                                lastModifiedBy: fileMetadata.lastModifiedBy?.user?.displayName
                            }
                        }
                    };
                    break;
                default:
                    throw new Error(`Unknown operation: ${operation}`);
            }
            // Add audit logging
            logger.audit('FILE_PARSER', {
                action: operation.toUpperCase(),
                targetResource: `file:${filename}`,
                result: 'SUCCESS',
                metadata: {
                    siteName,
                    filePath: filePath,
                    fileId: fileId,
                    operation,
                    fileSize: fileMetadata.size,
                    mimeType
                }
            });
            return {
                content: [{
                        type: "text",
                        text: JSON.stringify(result, null, 2)
                    }]
            };
        }
        catch (error) {
            logger.error(`Error parsing file ${filePath}:`, error);
            // Check if it's a parsing error vs access error
            if (error.message.includes('Unsupported file format')) {
                throw new Error(`File format not supported: ${error.message}. Supported formats: PDF, Word (doc/docx), Excel (xls/xlsx), PowerPoint (ppt/pptx), HTML, RTF, and text files.`);
            }
            else if (error.statusCode === 404) {
                throw new Error(`File not found: ${filePath} in site ${siteName}`);
            }
            else if (error.statusCode === 403) {
                throw new Error(`Access denied to file: ${filePath}. Check your permissions.`);
            }
            else {
                throw new Error(`Failed to parse file: ${error.message}`);
            }
        }
    }
    catch (error) {
        logger.error(`Error in file-parser tool:`, error);
        return {
            content: [{
                    type: "text",
                    text: JSON.stringify({
                        error: error.message,
                        operation: params.operation,
                        file: params.filePath,
                        site: params.siteName
                    }, null, 2)
                }],
            isError: true
        };
    }
});
// SharePoint Lists Tool
server.tool("sharepoint-lists", "Manage SharePoint list items - create, read, update, and delete list items. Useful for interacting with structured data stored in SharePoint lists.", sharePointListsSchema, (params, extra) => handleLists(params, extra, {}));
async function handleLists(params, _extra, ctx) {
    const { siteName, operation, listName, itemId, fields, filter, select, orderBy, maxResults, expand, dryRun, confirm, confirmToken, operations, continueOnError } = params;
    try {
        await policyGuard.enforce({
            tool: 'sharepoint-lists',
            verb: dryRun ? 'read' : listsVerb(operation),
            resource: `site:${siteName}/lists/${listName ?? ''}`
        });
        if (!graphClient) {
            throw new Error("Graph client not initialized. Authentication required.");
        }
        // Shared resolver: writes must target an exactly identified site.
        const isListWrite = listsVerb(operation) === 'write';
        const site = await findSite(siteName, graphClient, siteCache, { exact: isListWrite });
        if (dryRun && isListWrite && operation !== 'batch') {
            let list = null;
            let item = null;
            if (listName) {
                const found = await throttledRetry(() => graphClient.api(`/sites/${site.id}/lists/${encodeURIComponent(listName)}`).select('id,displayName,webUrl').get());
                list = { id: found.id, displayName: found.displayName, webUrl: found.webUrl };
                if (itemId) {
                    const existing = await throttledRetry(() => graphClient.api(`/sites/${site.id}/lists/${found.id}/items/${itemId}`).expand('fields').get());
                    item = { id: existing.id, fields: existing.fields };
                }
            }
            const preview = {
                dryRun: true,
                operation,
                site: { id: site.id, displayName: site.displayName, webUrl: site.webUrl },
                list,
                item,
                fieldsToApply: fields,
                note: 'No changes were made. Re-run without dryRun to apply.'
            };
            return { content: [{ type: "text", text: JSON.stringify(preview, null, 2) }] };
        }
        const listTarget = (name, id, f) => ({ id: id ?? 'new', name: f?.Title ?? (id ? `item ${id}` : 'new item'), path: name ? `list "${name}"` : undefined, kind: 'list item' });
        if (operation === 'batch') {
            if (!operations || operations.length === 0) {
                throw new Error("batch requires a non-empty 'operations' array");
            }
            const preview = { tool: 'sharepoint-lists', site: { id: site.id, displayName: site.displayName, webUrl: site.webUrl }, operations: [] };
            for (const [i, op] of operations.entries()) {
                const name = op.listName ?? listName;
                if (!name)
                    throw new Error(`batch entry ${i + 1} (${op.operation}) requires listName`);
                if (op.operation !== 'create_item' && !op.itemId)
                    throw new Error(`batch entry ${i + 1} (${op.operation}) requires itemId`);
                preview.operations.push({ index: i + 1, operation: op.operation, target: listTarget(name, op.itemId, op.fields), parameters: compact({ fields: op.fields }) });
            }
            if (dryRun) {
                return { content: [{ type: "text", text: `${renderPreview(preview)}\n\nDry run: nothing was changed.` }] };
            }
            const outcome = await confirmWrite(preview, { confirm, confirmToken }, elicitor, confirmOptions);
            if (!outcome.approved) {
                return { content: [{ type: "text", text: explainOutcome(outcome) }] };
            }
            const batchId = `batch-${Date.now().toString(36)}`;
            const outcomes = [];
            for (const [i, op] of operations.entries()) {
                // Exactly what was previewed: the entry's own fields and the site. No outer-call leakage.
                const single = await handleLists({ siteName, operation: op.operation, listName: op.listName ?? listName, itemId: op.itemId, fields: op.fields, dryRun: false }, _extra, { skipConfirm: true });
                const text = single?.content?.[0]?.text ?? '';
                const failed = single?.isError === true;
                outcomes.push({ index: i + 1, operation: op.operation, itemId: op.itemId, status: failed ? 'failed' : 'done', detail: text.slice(0, 500) });
                logger.audit('BATCH_ENTRY', { action: op.operation.toUpperCase(), result: failed ? 'FAILURE' : 'SUCCESS', targetResource: `list:${op.listName ?? listName}/${op.itemId ?? 'new'}`, metadata: { batchId, index: i + 1, siteName } });
                if (failed && !continueOnError) {
                    outcomes.push({ note: `Stopped after entry ${i + 1} failed. ${operations.length - i - 1} entr${operations.length - i - 1 === 1 ? 'y' : 'ies'} not run.` });
                    break;
                }
            }
            return { content: [{ type: "text", text: JSON.stringify({ batchId, site: preview.site, results: outcomes }, null, 2) }] };
        }
        if (isListWrite && !ctx.skipConfirm) {
            const preview = {
                tool: 'sharepoint-lists',
                site: { id: site.id, displayName: site.displayName, webUrl: site.webUrl },
                operations: [{ index: 1, operation, target: listTarget(listName, itemId, fields), parameters: compact({ fields }) }],
            };
            const outcome = await confirmWrite(preview, { confirm, confirmToken }, elicitor, confirmOptions);
            if (!outcome.approved) {
                return { content: [{ type: "text", text: explainOutcome(outcome) }] };
            }
        }
        let resultText = '';
        switch (operation) {
            case 'list_lists': {
                let request = graphClient.api(`/sites/${site.id}/lists`);
                if (select && select.length > 0) {
                    request = request.select(select);
                }
                const result = await throttledRetry(() => request.get());
                const lists = result.value || [];
                resultText = `Found ${lists.length} lists in site '${site.displayName}':\n\n`;
                resultText += JSON.stringify(lists, null, 2);
                break;
            }
            case 'get_items': {
                if (!listName) {
                    throw new Error("listName is required for get_items operation");
                }
                let request = graphClient.api(`/sites/${site.id}/lists/${listName}/items`);
                if (expand) {
                    request = request.expand(validateODataExpand(expand));
                }
                else {
                    request = request.expand('fields');
                }
                if (filter) {
                    request = request.filter(validateODataFilter(filter));
                }
                if (select && select.length > 0) {
                    request = request.select(select);
                }
                if (orderBy) {
                    request = request.orderby(validateODataOrderBy(orderBy));
                }
                request = request.top(maxResults || 100);
                const result = await throttledRetry(() => request.get());
                const items = result.value || [];
                resultText = `Found ${items.length} items in list '${listName}':\n\n`;
                resultText += JSON.stringify(items, null, 2);
                break;
            }
            case 'create_item': {
                if (!listName) {
                    throw new Error("listName is required for create_item operation");
                }
                if (!fields || Object.keys(fields).length === 0) {
                    throw new Error("fields are required for create_item operation");
                }
                // Non-idempotent: a retry after a lost response would create a second item.
                const result = await throttledRetry(() => graphClient.api(`/sites/${site.id}/lists/${listName}/items`).post({
                    fields: fields
                }), { idempotent: false });
                // Audit log
                logger.audit('LIST_ITEM_CREATED', {
                    action: 'CREATE',
                    targetResource: `list:${listName}`,
                    result: 'SUCCESS',
                    metadata: { siteName, fieldCount: Object.keys(fields).length }
                });
                resultText = `Item created successfully in list '${listName}':\n\n${JSON.stringify(result, null, 2)}`;
                break;
            }
            case 'update_item': {
                if (!listName || !itemId) {
                    throw new Error("listName and itemId are required for update_item operation");
                }
                if (!fields || Object.keys(fields).length === 0) {
                    throw new Error("fields are required for update_item operation");
                }
                const result = await throttledRetry(() => graphClient.api(`/sites/${site.id}/lists/${listName}/items/${itemId}/fields`).patch(fields));
                logger.audit('LIST_ITEM_UPDATED', {
                    action: 'UPDATE',
                    targetResource: `list:${listName}/item:${itemId}`,
                    result: 'SUCCESS',
                    metadata: { siteName, fieldCount: Object.keys(fields).length }
                });
                resultText = `Item '${itemId}' updated successfully in list '${listName}':\n\n${JSON.stringify(result, null, 2)}`;
                break;
            }
            case 'delete_item': {
                if (!listName || !itemId) {
                    throw new Error("listName and itemId are required for delete_item operation");
                }
                // A 404 on a retry means an earlier attempt already deleted the item.
                await throttledRetry(() => graphClient.api(`/sites/${site.id}/lists/${listName}/items/${itemId}`).delete(), { notFoundAfterRetryIsSuccess: true });
                logger.audit('LIST_ITEM_DELETED', {
                    action: 'DELETE',
                    targetResource: `list:${listName}/item:${itemId}`,
                    result: 'SUCCESS',
                    metadata: { siteName }
                });
                resultText = `Item '${itemId}' deleted successfully from list '${listName}'.`;
                break;
            }
            default:
                throw new Error(`Unknown operation: ${operation}`);
        }
        const response = {
            content: [{ type: "text", text: resultText }],
        };
        return addSecurityHeaders(response);
    }
    catch (error) {
        logger.error(`Error in sharepoint-lists tool:`, error);
        const errorMessage = error.message || 'Unknown error';
        return addSecurityHeaders({
            content: [{ type: "text", text: `Error: ${errorMessage}` }],
            isError: true
        });
    }
}
// Start the server with stdio transport
async function main() {
    // Validate security configuration
    const configValidation = SecurityConfigValidator.validateConfiguration();
    if (!configValidation.valid) {
        logger.error('Security configuration validation failed', { errors: configValidation.errors });
        if (process.env.NODE_ENV === 'production') {
            // In production, fail fast on configuration errors
            throw new Error(`Security configuration errors: ${configValidation.errors.join('; ')}`);
        }
        else {
            // In development, warn but continue
            logger.warn('Security configuration warnings (non-production mode)', { errors: configValidation.errors });
        }
    }
    // Log security configuration
    logger.info('Security configuration', {
        loggingEnabled: process.env.ENABLE_LOGGING === 'true',
        auditLogEnabled: process.env.ENABLE_AUDIT_LOG === 'true',
        strictPermissionMode: process.env.STRICT_PERMISSION_MODE === 'true',
        rateLimitMax: process.env.RATE_LIMIT_MAX || '100',
        rateLimitWindow: process.env.RATE_LIMIT_WINDOW_MS || '60000',
        environment: process.env.NODE_ENV || 'development',
        zeroTrustMonitoring: process.env.ENABLE_ZERO_TRUST_MONITORING !== 'false' ? 'ENABLED (Level 0.5 - Report Only)' : 'DISABLED'
    });
    // Determine authentication mode based on environment variables
    const useCertificate = process.env.USE_CERTIFICATE === 'true';
    const useInteractive = process.env.USE_INTERACTIVE === 'true';
    const useClientToken = process.env.USE_CLIENT_TOKEN === 'true';
    const initialAccessToken = process.env.ACCESS_TOKEN;
    let authMode;
    // Ensure only one authentication mode is enabled at a time
    const enabledModes = [
        useClientToken,
        useInteractive,
        useCertificate
    ].filter(Boolean);
    if (enabledModes.length > 1) {
        throw new Error("Multiple authentication modes enabled. Please enable only one of USE_CLIENT_TOKEN, USE_INTERACTIVE, or USE_CERTIFICATE.");
    }
    if (useClientToken) {
        authMode = AuthMode.ClientProvidedToken;
        if (!initialAccessToken) {
            logger.info("Client token mode enabled but no initial token provided. Token must be set via set-access-token tool.");
        }
    }
    else if (useInteractive) {
        authMode = AuthMode.Interactive;
    }
    else if (useCertificate) {
        authMode = AuthMode.Certificate;
    }
    else {
        // Check if we have client credentials environment variables
        const hasClientCredentials = process.env.TENANT_ID && process.env.CLIENT_ID && process.env.CLIENT_SECRET;
        if (hasClientCredentials) {
            authMode = AuthMode.ClientCredentials;
        }
        else {
            // Default to interactive mode for better user experience
            authMode = AuthMode.Interactive;
            logger.info("No authentication mode specified and no client credentials found. Defaulting to interactive mode.");
        }
    }
    logger.info(`Starting with authentication mode: ${authMode}`);
    // Get tenant ID and client ID with defaults only for interactive mode
    let tenantId;
    let clientId;
    if (authMode === AuthMode.Interactive) {
        // Interactive mode requires CLIENT_ID to be explicitly configured
        tenantId = process.env.TENANT_ID || DefaultTenantId;
        clientId = process.env.CLIENT_ID;
        if (!clientId) {
            throw new Error("Interactive mode requires CLIENT_ID environment variable. " +
                "Register an Azure AD application and set CLIENT_ID to your app's Application (client) ID.");
        }
        logger.info(`Interactive mode using tenant ID: ${tenantId}, client ID: ${clientId}`);
    }
    else {
        // All other modes require explicit values from environment variables
        tenantId = process.env.TENANT_ID;
        clientId = process.env.CLIENT_ID;
    }
    const clientSecret = process.env.CLIENT_SECRET;
    const certificatePath = process.env.CERTIFICATE_PATH;
    const certificatePassword = process.env.CERTIFICATE_PASSWORD; // optional
    // Validate required configuration
    if (authMode === AuthMode.ClientCredentials) {
        if (!tenantId || !clientId || !clientSecret) {
            throw new Error("Client credentials mode requires explicit TENANT_ID, CLIENT_ID, and CLIENT_SECRET environment variables");
        }
    }
    else if (authMode === AuthMode.Certificate) {
        if (!tenantId || !clientId || !certificatePath) {
            throw new Error("Certificate mode requires explicit TENANT_ID, CLIENT_ID, and CERTIFICATE_PATH environment variables");
        }
    }
    // Note: Client token mode can start without a token and receive it later
    const authConfig = {
        mode: authMode,
        tenantId,
        clientId,
        clientSecret,
        accessToken: initialAccessToken,
        redirectUri: process.env.REDIRECT_URI,
        certificatePath,
        certificatePassword
    };
    authManager = new AuthManager(authConfig);
    // Connect the transport BEFORE authenticating. Interactive sign-in can block for minutes
    // waiting on a browser or a device code, and the device code is only reachable through the
    // get-auth-status tool, so the server must already be answering tool calls.
    const transport = new StdioServerTransport();
    await server.connect(transport);
    // Persisted emergency mode and the local revocation list must be in memory before any
    // credential exists that a tool could use. The policy guard also awaits the emergency state
    // itself, so a tool call arriving during this window still sees a persisted shutdown.
    await Promise.all([emergencyControls.ready(), tokenRevocationManager.ready()]);
    // Always initialize. In client-token mode without a token this yields a logged-out
    // credential holder, so set-access-token can complete the sign-in later.
    try {
        await authManager.initialize();
        graphClient = createGraphClient(authManager.getGraphAuthProvider());
        authInitialization = { state: 'ready' };
        if (authMode === AuthMode.ClientProvidedToken && !initialAccessToken) {
            logger.info("Started in client token mode without a token. Use set-access-token to authenticate.");
        }
        else {
            logger.info(`Authentication initialized successfully using ${authMode} mode`);
        }
    }
    catch (error) {
        // Stay up in a logged-out state so the client can read the failure via get-auth-status.
        authInitialization = { state: 'failed', error: error?.message ?? String(error) };
        logger.error("Authentication initialization failed; server remains available in logged-out state", error);
    }
}
main().catch((error) => {
    logger.error("Fatal error in main():", error);
    logger.error("Fatal error in main()", error);
    process.exit(1);
});
