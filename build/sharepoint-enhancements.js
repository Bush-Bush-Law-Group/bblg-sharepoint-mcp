/**
 * SharePoint Enhanced Operations
 *
 * Advanced features for SharePoint file operations including:
 * - Microsoft Search API integration
 * - Rich metadata extraction
 * - Smart pagination
 * - Performance caching
 */
// Import the proper logger that writes to files
import { logger } from "./logger.js";
import { encodeDrivePath } from "./drive-path.js";
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
// ============================================
// 1. ENHANCED SEARCH - Microsoft Search API
// ============================================
/**
 * Advanced search using Microsoft Search API
 * Provides better relevance, performance, and features than basic Graph search
 */
export class EnhancedSharePointSearch {
    graphClient;
    constructor(graphClient) {
        this.graphClient = graphClient;
    }
    /**
     * Perform advanced search across SharePoint content
     * Uses the Microsoft Search API for better results
     */
    async searchContent(params) {
        const { query, siteId, folderPath, fileTypes, modifiedAfter, modifiedBefore, createdBy, minSize, maxSize, maxResults = 25, includeContent = false, searchFields = ['name', 'summary', 'content'] } = params;
        // Build KQL (Keyword Query Language) query
        let kqlQuery = query;
        const kqlFilters = [];
        // Add site filter
        if (siteId) {
            kqlFilters.push(`site:"${escapeKQL(siteId)}"`);
        }
        // Add path filter
        if (folderPath) {
            kqlFilters.push(`path:"${escapeKQL(folderPath)}"`);
        }
        // Add file type filters
        if (fileTypes && fileTypes.length > 0) {
            const typeFilter = fileTypes.map(type => `filetype:${type}`).join(' OR ');
            kqlFilters.push(`(${typeFilter})`);
        }
        // Add date range filters
        if (modifiedAfter) {
            kqlFilters.push(`lastmodifiedtime>=${modifiedAfter.toISOString()}`);
        }
        if (modifiedBefore) {
            kqlFilters.push(`lastmodifiedtime<=${modifiedBefore.toISOString()}`);
        }
        // Add author filter
        if (createdBy) {
            kqlFilters.push(`author:"${escapeKQL(createdBy)}"`);
        }
        // Add size filters
        if (minSize) {
            kqlFilters.push(`size>=${minSize}`);
        }
        if (maxSize) {
            kqlFilters.push(`size<=${maxSize}`);
        }
        // Combine query and filters
        if (kqlFilters.length > 0) {
            kqlQuery = `${query} AND ${kqlFilters.join(' AND ')}`;
        }
        try {
            // Use Microsoft Search API
            const searchRequest = {
                requests: [{
                        entityTypes: ['driveItem'], // Simplified to only driveItem to avoid template issues
                        query: {
                            queryString: kqlQuery
                        },
                        fields: searchFields,
                        from: 0,
                        size: maxResults,
                        // Add region for application permissions (required)
                        region: 'NAM', // North America region - adjust as needed
                        // Remove result templates as they cause issues with application permissions
                        // resultTemplateOptions removed
                        // Add query alterations for better results
                        queryAlterationOptions: {
                            enableSuggestion: true,
                            enableModification: true
                        },
                        // Sort by relevance by default
                        sortProperties: [{
                                name: '_score',
                                isDescending: true
                            }],
                        // Remove includeResultTemplate as it causes issues
                        trimDuplicates: true,
                        // Add content highlights
                        hitHighlight: includeContent ? {
                            fields: ['content', 'summary'],
                            fragmentSize: 200,
                            fragmentCount: 2
                        } : undefined
                    }]
            };
            logger.info('Executing Microsoft Search query', {
                query: kqlQuery,
                maxResults,
                entityTypes: searchRequest.requests[0].entityTypes
            });
            const response = await this.graphClient
                .api('/search/query')
                .post(searchRequest);
            // Process and enrich results
            const results = this.processSearchResults(response);
            return {
                query: query,
                totalResults: results.totalCount,
                hasMore: results.hasMore,
                results: results.items,
                suggestions: results.suggestions,
                queryAlterations: results.queryAlterations,
                executionTime: results.executionTime
            };
        }
        catch (error) {
            logger.error('Microsoft Search API error', error);
            throw new Error(`Search failed: ${error.message}`);
        }
    }
    /**
     * Process and enrich search results
     */
    processSearchResults(response) {
        const results = {
            items: [],
            totalCount: 0,
            hasMore: false,
            suggestions: [],
            queryAlterations: [],
            executionTime: 0
        };
        if (!response.value || response.value.length === 0) {
            return results;
        }
        const searchResponse = response.value[0];
        if (searchResponse.hitsContainers) {
            for (const container of searchResponse.hitsContainers) {
                results.totalCount += container.total || 0;
                results.hasMore = results.hasMore || container.moreResultsAvailable;
                if (container.hits) {
                    for (const hit of container.hits) {
                        const item = this.formatSearchHit(hit);
                        if (item) {
                            results.items.push(item);
                        }
                    }
                }
            }
        }
        // Extract suggestions
        if (searchResponse.queryAlterations) {
            results.queryAlterations = searchResponse.queryAlterations;
            results.suggestions = searchResponse.queryAlterations
                .filter((alt) => alt.alteredQuery)
                .map((alt) => alt.alteredQuery);
        }
        // Add execution time if available
        if (searchResponse.searchTerms && searchResponse.searchTerms[0]) {
            results.executionTime = searchResponse.searchTerms[0].executionTime || 0;
        }
        return results;
    }
    /**
     * Format individual search hit with rich metadata
     */
    formatSearchHit(hit) {
        const resource = hit.resource;
        if (!resource)
            return null;
        const formatted = {
            // Basic properties
            id: resource.id || hit.hitId,
            name: resource.name,
            displayName: resource.displayName || resource.name,
            // Enhanced metadata
            relevanceScore: hit.rank || hit._score,
            summary: hit.summary || resource.description,
            // File properties
            size: resource.size,
            sizeFormatted: this.formatFileSize(resource.size),
            mimeType: resource.file?.mimeType,
            fileExtension: resource.name ? resource.name.split('.').pop()?.toLowerCase() : undefined,
            // Timestamps
            createdDateTime: resource.createdDateTime,
            lastModifiedDateTime: resource.lastModifiedDateTime,
            lastAccessedDateTime: resource.lastAccessedDateTime,
            // People
            createdBy: resource.createdBy?.user?.displayName || resource.createdBy?.user?.email,
            lastModifiedBy: resource.lastModifiedBy?.user?.displayName || resource.lastModifiedBy?.user?.email,
            // Location
            webUrl: resource.webUrl,
            parentReference: resource.parentReference,
            path: resource.parentReference?.path?.replace('/drive/root:', '') || '/',
            siteId: resource.parentReference?.siteId,
            // Sharing & permissions
            isShared: !!resource.shared,
            sharingInfo: resource.shared,
            permissions: resource.permissions,
            // Content highlights (if requested)
            highlights: hit.highlights,
            contentSnippet: hit.highlights?.content?.[0] || hit.highlights?.summary?.[0],
            // Additional metadata
            version: resource.version,
            tags: resource.tags,
            sensitivity: resource.sensitivity,
            retentionLabel: resource.retentionLabel,
            classification: resource.classification
        };
        // Add folder-specific properties
        if (resource.folder) {
            formatted.type = 'folder';
            formatted.childCount = resource.folder.childCount;
            formatted.folderView = resource.folder.view;
        }
        else {
            formatted.type = 'file';
            // No @microsoft.graph.downloadUrl: a pre-authenticated URL is only handed out by get_content (F9).
            // Add file-specific metadata
            if (resource.file) {
                formatted.hashes = resource.file.hashes;
                formatted.processingMetadata = resource.file.processingMetadata;
            }
            // Add image metadata if available
            if (resource.image) {
                formatted.imageMetadata = {
                    height: resource.image.height,
                    width: resource.image.width
                };
            }
            // Add video metadata if available
            if (resource.video) {
                formatted.videoMetadata = {
                    duration: resource.video.duration,
                    bitrate: resource.video.bitrate,
                    framerate: resource.video.framerate
                };
            }
        }
        return formatted;
    }
    formatFileSize(bytes) {
        if (!bytes)
            return '0 B';
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${sizes[i]}`;
    }
}
// ============================================
// 2. ENHANCED METADATA EXTRACTION
// ============================================
/**
 * Extract rich metadata from SharePoint files
 */
export class SharePointMetadataExtractor {
    graphClient;
    constructor(graphClient) {
        this.graphClient = graphClient;
    }
    /**
     * Get comprehensive file metadata including all available properties
     */
    async getEnhancedMetadata(siteId, itemId) {
        try {
            // Fetch with all expanded properties
            const item = await this.graphClient
                .api(`/sites/${siteId}/drive/items/${itemId}`)
                .select([
                // Basic properties
                'id', 'name', 'size', 'eTag', 'cTag',
                // Timestamps
                'createdDateTime', 'lastModifiedDateTime',
                // People
                'createdBy', 'lastModifiedBy',
                // File/Folder specific
                'file', 'folder', 'image', 'video', 'audio', 'photo', 'location', 'package',
                // Sharing & permissions
                'shared', 'sharingInformation', 'permissions',
                // URLs
                'webUrl', 'webDavUrl',
                // References
                'parentReference', 'remoteItem',
                // Version & publication
                'version', 'publication',
                // Special properties
                'specialFolder', 'bundle', 'deleted', 'malware',
                // Taxonomy & compliance
                'retentionLabel', 'sensitivity', 'classification',
                // Analytics
                'activities', 'analytics',
                // Thumbnails
                'thumbnails'
            ].join(','))
                .expand([
                'permissions',
                'children',
                'thumbnails',
                'activities',
                'analytics',
                'versions'
            ].join(','))
                .get();
            // Extract and format all metadata
            const metadata = this.formatComprehensiveMetadata(item);
            // Get additional insights if available
            const insights = await this.getItemInsights(siteId, itemId);
            if (insights) {
                metadata.insights = insights;
            }
            return metadata;
        }
        catch (error) {
            logger.error('Failed to get enhanced metadata', error);
            throw new Error(`Metadata extraction failed: ${error.message}`);
        }
    }
    /**
     * Format comprehensive metadata into organized structure
     */
    formatComprehensiveMetadata(item) {
        return {
            // Core identification
            identity: {
                id: item.id,
                name: item.name,
                displayName: item.displayName || item.name,
                eTag: item.eTag,
                cTag: item.cTag
            },
            // Type and format
            type: {
                isFile: !!item.file,
                isFolder: !!item.folder,
                mimeType: item.file?.mimeType,
                extension: item.name ? item.name.split('.').pop()?.toLowerCase() : undefined,
                category: this.categorizeFile(item.name, item.file?.mimeType)
            },
            // Size and storage
            storage: {
                size: item.size,
                sizeFormatted: this.formatFileSize(item.size),
                quota: item.quota,
                deleted: item.deleted
            },
            // Timestamps
            timeline: {
                created: item.createdDateTime,
                modified: item.lastModifiedDateTime,
                accessed: item.lastAccessedDateTime,
                shared: item.shared?.sharedDateTime
            },
            // People and ownership
            people: {
                createdBy: this.formatUser(item.createdBy),
                lastModifiedBy: this.formatUser(item.lastModifiedBy),
                owner: this.formatUser(item.owner),
                sharedWith: item.permissions?.map((p) => this.formatPermission(p))
            },
            // Location and navigation
            location: {
                webUrl: item.webUrl,
                webDavUrl: item.webDavUrl,
                parentPath: item.parentReference?.path?.replace('/drive/root:', '') || '/',
                parentId: item.parentReference?.id,
                siteId: item.parentReference?.siteId,
                driveId: item.parentReference?.driveId
            },
            // Sharing and collaboration
            sharing: {
                isShared: !!item.shared,
                sharedInfo: item.shared,
                sharingInformation: item.sharingInformation,
                permissions: item.permissions,
                sharingLink: item.shared?.sharedLink,
                scope: item.shared?.scope
            },
            // Version control
            versioning: {
                version: item.version,
                publication: item.publication,
                versions: item.versions,
                versionCount: item.versions?.length || 0
            },
            // Media metadata (if applicable)
            media: {
                image: item.image ? {
                    height: item.image.height,
                    width: item.image.width,
                    orientation: item.image.orientation
                } : undefined,
                video: item.video ? {
                    duration: item.video.duration,
                    bitrate: item.video.bitrate,
                    framerate: item.video.framerate,
                    height: item.video.height,
                    width: item.video.width
                } : undefined,
                audio: item.audio ? {
                    duration: item.audio.duration,
                    bitrate: item.audio.bitrate,
                    album: item.audio.album,
                    artist: item.audio.artist,
                    title: item.audio.title
                } : undefined,
                photo: item.photo ? {
                    cameraMake: item.photo.cameraMake,
                    cameraModel: item.photo.cameraModel,
                    exposureTime: item.photo.exposureTime,
                    focalLength: item.photo.focalLength,
                    iso: item.photo.iso,
                    takenDateTime: item.photo.takenDateTime
                } : undefined
            },
            // Compliance and governance
            compliance: {
                retentionLabel: item.retentionLabel,
                sensitivity: item.sensitivity,
                classification: item.classification,
                malware: item.malware
            },
            // Analytics and activity
            analytics: {
                activities: item.activities,
                analytics: item.analytics,
                activityCount: item.activities?.length || 0
            },
            // Thumbnails
            thumbnails: item.thumbnails?.map((t) => ({
                id: t.id,
                small: t.small,
                medium: t.medium,
                large: t.large
            })),
            // Folder specific
            folder: item.folder ? {
                childCount: item.folder.childCount,
                view: item.folder.view
            } : undefined,
            // File specific
            file: item.file ? {
                hashes: item.file.hashes,
                processingMetadata: item.file.processingMetadata
            } : undefined
        };
    }
    /**
     * Get additional insights for the item
     */
    async getItemInsights(siteId, itemId) {
        try {
            const insights = await this.graphClient
                .api(`/sites/${siteId}/drive/items/${itemId}/analytics`)
                .get();
            return {
                views: insights.allTime?.views || 0,
                viewers: insights.allTime?.viewers || 0,
                lastViewedDateTime: insights.lastViewedDateTime,
                viewsByDay: insights.itemActivityStats
            };
        }
        catch (error) {
            // Insights might not be available for all items
            logger.debug('Could not fetch insights', { siteId, itemId });
            return null;
        }
    }
    formatUser(userInfo) {
        if (!userInfo)
            return null;
        return {
            displayName: userInfo.user?.displayName || userInfo.application?.displayName,
            email: userInfo.user?.email,
            id: userInfo.user?.id || userInfo.application?.id,
            type: userInfo.user ? 'user' : 'application'
        };
    }
    formatPermission(permission) {
        return {
            id: permission.id,
            roles: permission.roles,
            grantedTo: this.formatUser(permission.grantedTo),
            grantedDateTime: permission.grantedDateTime,
            invitation: permission.invitation,
            link: permission.link,
            shareId: permission.shareId
        };
    }
    categorizeFile(filename, mimeType) {
        const ext = filename?.toLowerCase().split('.').pop();
        const categories = {
            document: ['doc', 'docx', 'pdf', 'txt', 'rtf', 'odt'],
            spreadsheet: ['xls', 'xlsx', 'csv', 'ods'],
            presentation: ['ppt', 'pptx', 'odp'],
            image: ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'webp'],
            video: ['mp4', 'avi', 'mov', 'wmv', 'flv', 'mkv', 'webm'],
            audio: ['mp3', 'wav', 'flac', 'aac', 'ogg', 'wma'],
            code: ['js', 'ts', 'py', 'java', 'cpp', 'cs', 'html', 'css', 'json', 'xml'],
            archive: ['zip', 'rar', '7z', 'tar', 'gz', 'bz2'],
            data: ['json', 'xml', 'csv', 'sql', 'db']
        };
        for (const [category, extensions] of Object.entries(categories)) {
            if (ext && extensions.includes(ext)) {
                return category;
            }
        }
        // Check by MIME type
        if (mimeType) {
            if (mimeType.startsWith('image/'))
                return 'image';
            if (mimeType.startsWith('video/'))
                return 'video';
            if (mimeType.startsWith('audio/'))
                return 'audio';
            if (mimeType.startsWith('text/'))
                return 'document';
            if (mimeType.includes('spreadsheet'))
                return 'spreadsheet';
            if (mimeType.includes('presentation'))
                return 'presentation';
        }
        return 'other';
    }
    formatFileSize(bytes) {
        if (!bytes)
            return '0 B';
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${sizes[i]}`;
    }
}
// ============================================
// 3. SMART PAGINATION
// ============================================
/**
 * Intelligent pagination for large SharePoint folders
 */
export class SharePointPaginator {
    graphClient;
    pageSize;
    constructor(graphClient, pageSize = 50) {
        this.graphClient = graphClient;
        this.pageSize = pageSize;
    }
    /**
     * Get paginated results with iterator pattern
     */
    async *getPaginatedItems(params) {
        const { siteId, folderPath, filter, orderBy = 'name', select = ['id', 'name', 'size', 'lastModifiedDateTime', 'file', 'folder'], expand = [], pageSize = this.pageSize } = params;
        let endpoint = `/sites/${siteId}/drive/root/children`;
        if (folderPath) {
            // folderPath is a sanitised logical path; every segment is percent-encoded so it reaches
            // Graph as path text, never as URL syntax.
            endpoint = `/sites/${siteId}/drive/root:/${encodeDrivePath(folderPath)}:/children`;
        }
        let nextLink = endpoint;
        let pageNumber = 0;
        let totalItems = 0;
        while (nextLink) {
            try {
                pageNumber++;
                logger.info(`Fetching page ${pageNumber}`, { endpoint: nextLink });
                let request;
                if (nextLink === endpoint) {
                    // First request - build with parameters
                    request = this.graphClient.api(nextLink)
                        .top(pageSize)
                        .select(select.join(','));
                    if (filter) {
                        request = request.filter(filter);
                    }
                    if (orderBy) {
                        request = request.orderby(orderBy);
                    }
                    if (expand.length > 0) {
                        request = request.expand(expand.join(','));
                    }
                }
                else {
                    // Subsequent requests - use the @odata.nextLink directly
                    request = this.graphClient.api(validateGraphNextLink(nextLink));
                }
                const response = await request.get();
                const items = response.value || [];
                totalItems += items.length;
                // Yield the current page of results
                yield {
                    pageNumber,
                    items,
                    itemCount: items.length,
                    totalItemsSoFar: totalItems,
                    hasMore: !!response['@odata.nextLink']
                };
                // Get next page link
                nextLink = response['@odata.nextLink'] || null;
            }
            catch (error) {
                logger.error(`Error fetching page ${pageNumber}`, error);
                throw new Error(`Pagination failed on page ${pageNumber}: ${error.message}`);
            }
        }
    }
    /**
     * Get all items with automatic pagination (be careful with large datasets)
     */
    async getAllItems(params) {
        const allItems = [];
        for await (const page of this.getPaginatedItems(params)) {
            allItems.push(...page.items);
            // Optional: Add a safety limit
            if (allItems.length > 10000) {
                logger.warn('Reached maximum item limit of 10000');
                break;
            }
        }
        return allItems;
    }
    /**
     * Get a specific page of results
     */
    async getPage(params) {
        const { pageNumber: targetPage, ...iteratorParams } = params;
        let currentPage = 0;
        for await (const page of this.getPaginatedItems(iteratorParams)) {
            currentPage++;
            if (currentPage === targetPage) {
                return page;
            }
        }
        throw new Error(`Page ${targetPage} not found`);
    }
    /**
     * Stream items with callback for processing
     */
    async streamItems(params, callback) {
        let globalIndex = 0;
        for await (const page of this.getPaginatedItems(params)) {
            for (const item of page.items) {
                await callback(item, globalIndex++);
            }
        }
        return globalIndex;
    }
}
// ============================================
// 4. PERFORMANCE CACHING
// ============================================
/**
 * Multi-layer caching system for SharePoint operations
 */
export class SharePointCache {
    memoryCache;
    maxCacheSize;
    defaultTTL;
    cleanupTimer;
    constructor(maxCacheSize = 1000, defaultTTL = 300000) {
        this.memoryCache = new Map();
        this.maxCacheSize = maxCacheSize;
        this.defaultTTL = defaultTTL;
        // Set up periodic cleanup
        this.cleanupTimer = setInterval(() => this.cleanup(), 60000); // Clean up every minute
        this.cleanupTimer.unref?.(); // never keeps the process alive
    }
    /** Stops the cleanup interval and drops every entry. Safe to call more than once. */
    dispose() {
        if (this.cleanupTimer) {
            clearInterval(this.cleanupTimer);
            this.cleanupTimer = null;
        }
        this.memoryCache.clear();
    }
    /**
     * Get or fetch data with caching
     */
    async getOrFetch(key, fetcher, options) {
        const { ttl = this.defaultTTL, forceRefresh = false, cacheNullResults = false } = options || {};
        // Check if we should skip cache
        if (!forceRefresh) {
            const cached = this.get(key);
            if (cached !== undefined) {
                logger.debug(`Cache hit for key: ${key}`);
                return cached;
            }
        }
        logger.debug(`Cache miss for key: ${key}`);
        try {
            // Fetch fresh data
            const data = await fetcher();
            // Cache the result
            if (data !== null || cacheNullResults) {
                this.set(key, data, ttl);
            }
            return data;
        }
        catch (error) {
            // Check if we have stale data we can return
            const stale = this.getStale(key);
            if (stale !== undefined) {
                logger.warn(`Returning stale cache for key: ${key} due to error`, error);
                return stale;
            }
            throw error;
        }
    }
    /**
     * Get cached value if not expired
     */
    get(key) {
        const entry = this.memoryCache.get(key);
        if (!entry) {
            return undefined;
        }
        if (Date.now() > entry.expiresAt) {
            // Don't delete yet - keep for stale cache fallback
            return undefined;
        }
        // Update access time for LRU
        entry.lastAccessed = Date.now();
        return entry.value;
    }
    /**
     * Get stale cached value (expired but still in memory)
     */
    getStale(key) {
        const entry = this.memoryCache.get(key);
        return entry?.value;
    }
    /**
     * Set cache value
     */
    set(key, value, ttl) {
        // Enforce cache size limit
        if (this.memoryCache.size >= this.maxCacheSize) {
            this.evictLRU();
        }
        this.memoryCache.set(key, {
            value,
            expiresAt: Date.now() + (ttl || this.defaultTTL),
            lastAccessed: Date.now(),
            size: this.estimateSize(value)
        });
        logger.debug(`Cached key: ${key}`);
    }
    /**
     * Invalidate specific cache entry
     */
    invalidate(key) {
        this.memoryCache.delete(key);
        logger.debug(`Invalidated cache key: ${key}`);
    }
    /**
     * Invalidate cache entries matching pattern
     */
    invalidatePattern(pattern) {
        const regex = typeof pattern === 'string' ? new RegExp(pattern) : pattern;
        let count = 0;
        for (const key of this.memoryCache.keys()) {
            if (regex.test(key)) {
                this.memoryCache.delete(key);
                count++;
            }
        }
        logger.debug(`Invalidated ${count} cache entries matching pattern`);
        return count;
    }
    /**
     * Clear all cache
     */
    clear() {
        const size = this.memoryCache.size;
        this.memoryCache.clear();
        logger.info(`Cleared ${size} cache entries`);
    }
    /**
     * Get cache statistics
     */
    getStats() {
        let totalSize = 0;
        let expiredCount = 0;
        const now = Date.now();
        for (const entry of this.memoryCache.values()) {
            totalSize += entry.size;
            if (now > entry.expiresAt) {
                expiredCount++;
            }
        }
        return {
            entries: this.memoryCache.size,
            expiredEntries: expiredCount,
            activeEntries: this.memoryCache.size - expiredCount,
            totalSizeBytes: totalSize,
            totalSizeMB: (totalSize / 1024 / 1024).toFixed(2),
            hitRate: this.calculateHitRate()
        };
    }
    /**
     * Clean up expired entries
     */
    cleanup() {
        const now = Date.now();
        const expiredKeys = [];
        for (const [key, entry] of this.memoryCache.entries()) {
            // Keep stale entries for a bit longer (2x TTL)
            if (now > entry.expiresAt + this.defaultTTL) {
                expiredKeys.push(key);
            }
        }
        for (const key of expiredKeys) {
            this.memoryCache.delete(key);
        }
        if (expiredKeys.length > 0) {
            logger.debug(`Cleaned up ${expiredKeys.length} expired cache entries`);
        }
    }
    /**
     * Evict least recently used entry
     */
    evictLRU() {
        let lruKey = null;
        let lruTime = Date.now();
        for (const [key, entry] of this.memoryCache.entries()) {
            if (entry.lastAccessed < lruTime) {
                lruTime = entry.lastAccessed;
                lruKey = key;
            }
        }
        if (lruKey) {
            this.memoryCache.delete(lruKey);
            logger.debug(`Evicted LRU cache entry: ${lruKey}`);
        }
    }
    /**
     * Estimate size of cached value
     */
    estimateSize(value) {
        try {
            return JSON.stringify(value).length;
        }
        catch {
            return 1000; // Default estimate
        }
    }
    /**
     * Calculate cache hit rate (would need to track hits/misses)
     */
    calculateHitRate() {
        // This would need additional tracking of hits and misses
        return 'N/A';
    }
}
// ============================================
// 5. INTEGRATED SHAREPOINT OPERATIONS
// ============================================
/**
 * Main class that integrates all enhancements
 */
export class EnhancedSharePointOperations {
    graphClient;
    search;
    metadata;
    paginator; // Made public for direct access
    cache;
    constructor(graphClient) {
        this.graphClient = graphClient;
        this.search = new EnhancedSharePointSearch(graphClient);
        this.metadata = new SharePointMetadataExtractor(graphClient);
        this.paginator = new SharePointPaginator(graphClient);
        this.cache = new SharePointCache();
    }
    /**
     * Perform enhanced search with caching
     */
    async searchFiles(params) {
        const cacheKey = `search:${JSON.stringify(params)}`;
        return this.cache.getOrFetch(cacheKey, () => this.search.searchContent(params), { ttl: 120000 } // Cache for 2 minutes
        );
    }
    /**
     * Get file with enhanced metadata and caching
     */
    async getFileWithMetadata(siteId, itemId) {
        const cacheKey = `file:${siteId}:${itemId}`;
        return this.cache.getOrFetch(cacheKey, () => this.metadata.getEnhancedMetadata(siteId, itemId), { ttl: 300000 } // Cache for 5 minutes
        );
    }
    /**
     * List folder contents with pagination
     */
    async *listFolderPaginated(params) {
        yield* this.paginator.getPaginatedItems(params);
    }
    /**
     * Batch operations for performance
     */
    async batchGetFiles(siteId, fileIds) {
        const batchSize = 20; // Graph API batch limit
        const results = [];
        for (let i = 0; i < fileIds.length; i += batchSize) {
            const batch = fileIds.slice(i, i + batchSize);
            const batchRequests = batch.map(id => ({
                id: id,
                method: 'GET',
                url: `/sites/${siteId}/drive/items/${id}`
            }));
            const batchResponse = await this.graphClient
                .api('/$batch')
                .post({ requests: batchRequests });
            results.push(...batchResponse.responses);
        }
        return results;
    }
    /**
     * Invalidate cache for specific operations
     */
    invalidateCache(pattern) {
        if (pattern) {
            return this.cache.invalidatePattern(pattern);
        }
        this.cache.clear();
    }
    /**
     * Get cache statistics
     */
    getCacheStats() {
        return this.cache.getStats();
    }
    /** Releases the cache and its timer. Call when the underlying Graph client is replaced. */
    dispose() {
        this.cache.dispose();
    }
}
// Export singleton instance for easy use
export function createEnhancedSharePointOperations(graphClient) {
    return new EnhancedSharePointOperations(graphClient);
}
