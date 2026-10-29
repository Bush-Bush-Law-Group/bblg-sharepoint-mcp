// Helper to create properly typed Zod schemas that MCP SDK can recognize
import { z } from "zod";
/**
 * A relative API path: exactly one leading '/', then no '//' anywhere (a scheme or protocol-relative
 * host), no '?' or '#' (query options belong in queryParams), no whitespace or backslashes, and no
 * '.' or '..' segment in plain or %2e form (the URL parser resolves them before the request is sent,
 * so '/users/../roleManagement' would reach Graph as '/roleManagement' and evade path checks).
 * Anchoring the path this way keeps the request origin fixed to the API host whatever follows:
 * '@' after the first slash is ordinary path text (e.g. /users/alice@contoso.com), never userinfo.
 */
const RELATIVE_API_PATH = /^(?!.*\/(?:\.|%2e){1,2}(?:\/|$))\/(?!\/)(?:(?!\/\/)[^?#\s\\])*$/i;
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/**
 * A drive folder/file path as typed by the model. It is interpolated into `root:/{path}:/children`
 * URLs, so it may not contain URL delimiters ('?', '#', ':'), backslashes, control characters or the
 * characters SharePoint itself forbids in names. '..' is rejected at runtime by sanitizePath.
 */
const DRIVE_PATH = /^[^?#:\\*"<>|\x00-\x1f\x7f]*$/;
const DRIVE_PATH_MESSAGE = "Path must not contain ?, #, :, \\, *, \", <, >, | or control characters";
const drivePath = (description) => z.string().max(1024).regex(DRIVE_PATH, DRIVE_PATH_MESSAGE).optional().describe(description);
/** Comma-separated file extensions, e.g. 'pdf,docx'. Interpolated into OData endswith() and KQL filetype: clauses. */
const FILE_TYPE = /^[a-z0-9]{1,10}(,[a-z0-9]{1,10})*$/i;
/** ISO 8601 date or date-time. Interpolated into OData $filter and KQL date clauses. */
const ISO_DATE_TIME = /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d{1,7})?)?(Z|[+-]\d{2}:\d{2})?)?$/;
const isoDate = (description) => z.string().regex(ISO_DATE_TIME, "Must be an ISO 8601 date (YYYY-MM-DD) or date-time")
    .refine(value => !Number.isNaN(Date.parse(value)), "Must be a valid calendar date")
    .optional().describe(description);
/** A KQL author:"…" value: no quotes, backslashes or control characters. */
const CREATED_BY = /^[^"\\\x00-\x1f\x7f]{1,256}$/;
/** An OData property path for $select, e.g. 'Title' or 'fields/Status'. */
const ODATA_PROPERTY_PATH = /^[A-Za-z0-9_/]+$/;
// Microsoft Graph tool schema - export as shape, not z.object
export const microsoftGraphSchema = {
    apiType: z.enum(["graph", "azure"]).describe("Type of Microsoft API to query. Options: 'graph' for Microsoft Graph (Entra) or 'azure' for Azure Resource Management."),
    path: z.string().min(1).max(2048).regex(RELATIVE_API_PATH, "path must be a relative API path starting with '/' (no scheme or host, no '//', no '.' or '..' segments, no '?' or '#'; put query options in queryParams)")
        .describe("Relative API path to call, starting with '/' (e.g. '/users', '/groups', '/resourceGroups'). Never a full URL; query options go in queryParams."),
    method: z.enum(["get", "post", "put", "patch", "delete"]).describe("HTTP method to use"),
    apiVersion: z.string().optional().describe("Azure Resource Management API version (required for apiType Azure)"),
    subscriptionId: z.string().regex(GUID, "subscriptionId must be a GUID").optional().describe("Azure Subscription ID as a GUID (for Azure Resource Management)."),
    queryParams: z.record(z.string(), z.string()).optional().describe("Query parameters for the request"),
    body: z.record(z.string(), z.any()).optional().describe("The request body (for POST, PUT, PATCH)"),
    confirm: z.boolean().optional().describe("Two-step confirmation for write operations, only when the server runs with CONFIRM_WRITES=token and the client cannot prompt the user: set true together with the confirmToken from the preview you were shown"),
    confirmToken: z.string().optional().describe("Single-use token from the write preview (CONFIRM_WRITES=token only); valid for 10 minutes and bound to the previewed targets"),
    graphApiVersion: z.enum(["v1.0", "beta"]).optional().describe("Microsoft Graph API version to use"),
    fetchAll: z.boolean().optional().default(false).describe("Set to true to automatically fetch all pages for list results (e.g., users, groups). Default is false."),
    consistencyLevel: z.string().optional().describe("Graph API ConsistencyLevel header. ADVISED to be set to 'eventual' for Graph GET requests using advanced query parameters ($filter, $count, $search, $orderby)."),
};
// Set access token tool schema - export as shape
export const setAccessTokenSchema = {
    accessToken: z.string().describe("The access token obtained from Microsoft Graph authentication"),
    expiresOn: z.string().optional().describe("Token expiration time in ISO format (optional, defaults to 1 hour from now)"),
    confirm: z.boolean().optional().describe("Two-step confirmation of the identity change, only when the server runs with CONFIRM_WRITES=token and the client cannot prompt the user: set true together with the confirmToken from the preview you were shown"),
    confirmToken: z.string().optional().describe("Single-use token from the identity-change preview (CONFIRM_WRITES=token only); valid for 10 minutes and bound to the previewed access token")
};
// Get auth status schema (empty) - export as shape
export const getAuthStatusSchema = {};
// Add graph permission schema - export as shape
export const addGraphPermissionSchema = {
    scopes: z.array(z.string()).describe("Array of Microsoft Graph permission scopes to request (e.g., ['User.Read', 'Mail.ReadWrite', 'Directory.Read.All'])")
};
// SharePoint site discovery schema - export as shape
export const sharePointSiteDiscoverySchema = {
    operation: z.enum([
        "list_all", // List all accessible sites
        "search", // Search sites by name or description
        "my_sites", // Get user's followed/recent sites
        "hub_sites", // List hub sites
        "team_sites", // List team sites only
        "communication_sites", // List communication sites only
        "get_details", // Get details for specific sites
        "continue" // Continue from previous results using token
    ]).describe("Type of site discovery operation"),
    searchQuery: z.string().optional().describe("Search query for finding sites (used with 'search' operation)"),
    maxResults: z.number().int().min(1).max(5000).optional().describe("Optional limit on number of sites to return (1-5000). If not specified, returns up to the server's fetch-all cap (MAX_FETCH_ALL_ITEMS) with automatic pagination"),
    orderBy: z.enum(["displayName", "createdDateTime", "lastModifiedDateTime"]).optional().default("displayName").describe("Sort order for results"),
    includeDetails: z.boolean().optional().default(false).describe("Include additional site details like storage quota and template"),
    includeSubsites: z.boolean().optional().default(false).describe("Include subsites in the results"),
    summaryMode: z.boolean().optional().default(true).describe("Return summary when results exceed 50 items (recommended for large datasets)"),
    pageSize: z.number().int().min(1).max(999).optional().default(20).describe("Number of items per page when using pagination (1-999)"),
    continuationToken: z.string().optional().describe("Token to continue from previous results (used with 'continue' operation)"),
    siteIds: z.array(z.string()).optional().describe("Specific site IDs to get details for (used with 'get_details' operation)")
};
// File parser tool schema - export as shape
export const fileParserSchema = {
    siteName: z.string().describe("Name or URL of the SharePoint site"),
    filePath: drivePath("Path to the file within the SharePoint site (e.g., 'Documents/folder/file.pdf')"),
    fileId: z.string().regex(/^[A-Za-z0-9!_-]{1,200}$/, "File ID must be alphanumeric (with !_-), max 200 characters").optional().describe("Direct file ID from SharePoint (e.g., '01B65XAEES6VTGM5KFC5AYMZJX4RXAEMNN')"),
    operation: z.enum([
        "parse", // Parse document and extract text
        "summarize", // Parse and provide summary
        "metadata" // Extract only metadata
    ]).optional().default("parse").describe("Operation to perform on the file"),
    includeMetadata: z.boolean().optional().default(true).describe("Include document metadata in response"),
    extractImages: z.boolean().optional().default(false).describe("Extract and describe images (if supported)")
};
// SharePoint site files tool schema - export as shape
export const sharePointSiteFilesSchema = {
    siteName: z.string().describe("Name or URL of the SharePoint site (e.g., 'Intranet', 'HR Portal', or site URL)"),
    operation: z.enum([
        "search", // Search for files with query
        "list", // List files in a folder
        "get_metadata", // Get detailed file information
        "get_content", // Download file content
        "list_folders", // List folder structure
        "recent", // Get recently modified files
        "by_type", // Get files by type
        "large_files", // Find large files
        "shared", // Get shared files
        "site_info", // Get site information
        "create_folder", // Create a new folder
        "delete", // Delete a file or folder
        "rename", // Rename a file or folder
        "copy", // Copy a file or folder
        "move", // Move a file or folder
        "update_content", // Replace an existing file's content (keeps ID, name, sharing, version history)
        "batch" // Several write operations previewed and confirmed once, then run in order
    ]).describe("Operation to perform on the SharePoint site"),
    // Search and filter parameters
    searchQuery: z.string().optional().describe("Search query for finding files (supports keywords, phrases)"),
    fileType: z.string().regex(FILE_TYPE, "fileType must be one or more extensions separated by commas, e.g. 'pdf,docx'").optional().describe("File type filter: one or more extensions separated by commas, no spaces (e.g. 'pdf', 'docx,xlsx')"),
    folderPath: drivePath("Folder path within the site (e.g., 'Documents/Projects/2024')"),
    // Advanced filters
    modifiedAfter: isoDate("ISO 8601 date or date-time - files modified after this date"),
    modifiedBefore: isoDate("ISO 8601 date or date-time - files modified before this date"),
    createdBy: z.string().regex(CREATED_BY, "createdBy must not contain quotes, backslashes or control characters (max 256 chars)").optional().describe("Filter by creator's email or name"),
    minSize: z.number().int().min(0).optional().describe("Minimum file size in bytes"),
    maxSize: z.number().int().min(0).optional().describe("Maximum file size in bytes"),
    // Control parameters
    maxResults: z.number().int().min(1).max(999).optional().describe("Maximum number of results to return (1-999; operation-specific default when omitted)"),
    orderBy: z.enum(["name", "modified", "size", "createdDateTime"]).optional().default("modified").describe("Sort order for results"),
    descending: z.boolean().optional().default(true).describe("Sort in descending order"),
    // File operation parameters
    fileId: z.string().regex(/^[A-Za-z0-9!_-]{1,200}$/, "File ID must be alphanumeric (with !_-), max 200 characters").optional().describe("File ID for get_metadata or get_content operations"),
    includeSubfolders: z.boolean().optional().default(false).describe("Include files from subfolders in search/list operations"),
    includePermissions: z.boolean().optional().default(false).describe("Include sharing and permission info in results"),
    // Enhanced features parameters
    useAdvancedSearch: z.boolean().optional().default(false).describe("Use Microsoft Search API for better search results (requires searchQuery)"),
    pageNumber: z.number().int().min(1).optional().describe("Page number for paginated results (starts from 1)"),
    pageSize: z.number().int().min(1).max(999).optional().default(50).describe("Number of items per page for pagination (default 50, max 999)"),
    // CRUD operation parameters
    newName: z.string().regex(/^[^/\\:*?"<>|\x00-\x1f]{1,255}$/, "Name must not contain path separators or special characters, max 255 chars").optional().describe("New name for rename operation"),
    destinationPath: drivePath("Destination folder path for move/copy operations"),
    folderName: z.string().regex(/^[^/\\:*?"<>|\x00-\x1f]{1,255}$/, "Folder name must not contain path separators or special characters, max 255 chars").optional().describe("Name for create_folder operation"),
    content: z.string().optional().describe("New file content for update_content. Plain text by default; set contentEncoding to 'base64' for binary files."),
    contentEncoding: z.enum(["text", "base64"]).optional().default("text").describe("How 'content' is encoded: 'text' (UTF-8) or 'base64' (binary)"),
    daysBack: z.number().min(1).max(365).optional().default(7).describe("Number of days to look back for 'recent' operation (default 7, max 365)"),
    dryRun: z.boolean().optional().default(false).describe("For write operations: resolve the exact site and target item and report what WOULD change, without changing anything"),
    confirm: z.boolean().optional().describe("Two-step confirmation for write operations, only when the server runs with CONFIRM_WRITES=token and the client cannot prompt the user: set true together with the confirmToken from the preview you were shown"),
    confirmToken: z.string().optional().describe("Single-use token from the write preview (CONFIRM_WRITES=token only); valid for 10 minutes and bound to the previewed targets"),
    operations: z.array(z.object({
        operation: z.enum(["create_folder", "delete", "rename", "copy", "move", "update_content"]),
        fileId: z.string().regex(/^[A-Za-z0-9!_-]{1,200}$/).optional(),
        folderPath: z.string().max(1024).regex(DRIVE_PATH, DRIVE_PATH_MESSAGE).optional(),
        folderName: z.string().regex(/^[^/\\:*?"<>|\x00-\x1f]{1,255}$/).optional(),
        newName: z.string().regex(/^[^/\\:*?"<>|\x00-\x1f]{1,255}$/).optional(),
        destinationPath: z.string().max(1024).regex(DRIVE_PATH, DRIVE_PATH_MESSAGE).optional(),
        content: z.string().optional(),
        contentEncoding: z.enum(["text", "base64"]).optional()
    })).min(1).max(50).optional().describe("For the 'batch' operation: the write operations to preview together, confirm once, and run in order (same site, max 50)"),
    continueOnError: z.boolean().optional().default(false).describe("Batch only: keep running after a failed entry instead of stopping")
};
// SharePoint lists tool schema - export as shape
export const sharePointListsSchema = {
    siteName: z.string().describe("Name or URL of the SharePoint site"),
    operation: z.enum([
        "list_lists", // List all lists in a site
        "get_items", // Get items from a list
        "create_item", // Create a new list item
        "update_item", // Update an existing list item
        "delete_item", // Delete a list item
        "batch" // Several write operations previewed and confirmed once, then run in order
    ]).describe("Operation to perform"),
    listName: z.string().regex(/^[A-Za-z0-9 _\-]{1,255}$/, "List name must be alphanumeric (with spaces, hyphens, underscores), max 255 chars").optional().describe("Name or ID of the SharePoint list"),
    itemId: z.string().regex(/^[A-Za-z0-9_\-]{1,200}$/, "Item ID must be alphanumeric, max 200 chars").optional().describe("List item ID (for update/delete operations)"),
    fields: z.record(z.string(), z.any()).optional().describe("Field values for create/update operations (e.g., {'Title': 'New Item', 'Status': 'Active'})"),
    filter: z.string().optional().describe("OData filter expression (e.g., \"Status eq 'Active'\")"),
    select: z.array(z.string().regex(ODATA_PROPERTY_PATH, "select entries must be OData property paths such as 'Title' or 'fields/Status'")).max(100).optional().describe("Fields to include in response (OData property paths, e.g. ['Title', 'fields/Status'])"),
    orderBy: z.string().optional().describe("Field to sort by"),
    maxResults: z.number().int().min(1).max(5000).optional().default(100).describe("Maximum items to return (1-5000)"),
    expand: z.string().optional().describe("OData expand expression for related data"),
    dryRun: z.boolean().optional().default(false).describe("For write operations: resolve the exact site, list and item and report what WOULD change, without changing anything"),
    confirm: z.boolean().optional().describe("Two-step confirmation for write operations, only when the server runs with CONFIRM_WRITES=token and the client cannot prompt the user: set true together with the confirmToken from the preview you were shown"),
    confirmToken: z.string().optional().describe("Single-use token from the write preview (CONFIRM_WRITES=token only); valid for 10 minutes and bound to the previewed targets"),
    operations: z.array(z.object({
        operation: z.enum(["create_item", "update_item", "delete_item"]),
        listName: z.string().regex(/^[A-Za-z0-9 _\-]{1,255}$/).optional(),
        itemId: z.string().regex(/^[A-Za-z0-9_\-]{1,200}$/).optional(),
        fields: z.record(z.string(), z.any()).optional()
    })).min(1).max(50).optional().describe("For the 'batch' operation: the list writes to preview together, confirm once, and run in order (same site, max 50)"),
    continueOnError: z.boolean().optional().default(false).describe("Batch only: keep running after a failed entry instead of stopping")
};
