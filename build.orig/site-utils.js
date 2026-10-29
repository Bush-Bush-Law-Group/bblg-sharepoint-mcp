import { executeWithRetry } from "./api-utils.js";
import { logger } from "./logger.js";
function escapeKQL(input) {
    return input.replace(/["':\\*?<>|&]/g, (char) => `\\${char}`);
}
const SITE_FIELDS = 'id,name,displayName,webUrl,description,createdDateTime';
/** Graph composite site ID: "hostname,siteCollectionGuid,siteGuid". */
export function isSiteId(value) {
    return /^[a-z0-9.-]+\.[a-z]+,[0-9a-f-]+,[0-9a-f-]+$/i.test(value.trim());
}
/** Authentication and policy failures must surface as themselves, never as "site not found". */
function isAuthProblem(error) {
    const message = error?.message ?? '';
    return /not signed in|revoked|authentication not initialized|graph client not initialized|failed to acquire access token|emergency|read-only mode/i.test(message)
        || error?.statusCode === 401;
}
function describe(site) {
    return `${site.displayName ?? site.name} <${site.webUrl}> (id: ${site.id})`;
}
function exactNameMatch(sites, siteName) {
    const wanted = siteName.trim().toLowerCase();
    return sites.find((site) => site.displayName?.toLowerCase() === wanted ||
        site.name?.toLowerCase() === wanted ||
        site.webUrl?.toLowerCase() === wanted.replace(/\/+$/, ''));
}
/**
 * Find a SharePoint site by ID, URL or name, with caching.
 * Read paths may fall back to fuzzy matching. Write paths pass { exact: true } and never do.
 */
export async function findSite(siteName, graphClient, siteCache, options = {}) {
    const exact = options.exact === true;
    // Exact and fuzzy resolutions are cached separately: a fuzzy read must never satisfy a write.
    const cacheKey = `site:${exact ? 'exact' : 'fuzzy'}:${siteName.trim().toLowerCase()}`;
    const cached = siteCache.get(cacheKey);
    if (cached) {
        logger.debug(`Site found in cache: ${cached.displayName}`);
        return cached;
    }
    const remember = (site) => { siteCache.set(cacheKey, site); return site; };
    try {
        // 1. Composite site ID: unambiguous, direct.
        if (isSiteId(siteName)) {
            const response = await executeWithRetry(async () => graphClient.api(`/sites/${siteName.trim()}`).select(SITE_FIELDS).get());
            if (response?.id)
                return remember(response);
        }
        // 2. Full URL: direct hostname:path lookup.
        if (siteName.includes('sharepoint.com')) {
            try {
                const url = new URL(siteName);
                const siteEndpoint = `/sites/${url.hostname}:${url.pathname.replace(/\/+$/, '')}`;
                logger.info(`Trying direct site access: ${siteEndpoint}`);
                const response = await executeWithRetry(async () => graphClient.api(siteEndpoint).select(`${SITE_FIELDS},siteCollection,drive`).get());
                if (response?.id) {
                    logger.info(`Found site by URL: ${response.displayName || response.name}`);
                    return remember(response);
                }
            }
            catch (urlError) {
                if (isAuthProblem(urlError))
                    throw urlError;
                logger.debug(`Direct URL access failed, trying other methods: ${urlError.message}`);
            }
        }
        // 3. Site path under /sites/<name>.
        if (!siteName.includes('http')) {
            try {
                const response = await graphClient
                    .api(`/sites/root:/sites/${encodeURIComponent(siteName.trim())}`)
                    .select(SITE_FIELDS)
                    .get();
                if (response?.id)
                    return remember(response);
            }
            catch (relativeError) {
                if (isAuthProblem(relativeError))
                    throw relativeError;
                logger.debug(`Relative path access failed: ${relativeError}`);
            }
        }
        // 4. Search: exact name match is accepted in both modes; first-result only for reads.
        let candidates = [];
        try {
            const searchResponse = await graphClient
                .api('/sites')
                .search(`"${escapeKQL(siteName)}"`)
                .select(SITE_FIELDS)
                .top(10)
                .get();
            candidates = searchResponse?.value ?? [];
            const match = exactNameMatch(candidates, siteName);
            if (match)
                return remember(match);
            if (!exact && candidates.length > 0) {
                logger.info(`Using first search result for '${siteName}': ${candidates[0].displayName}`);
                return remember(candidates[0]);
            }
        }
        catch (searchError) {
            if (isAuthProblem(searchError))
                throw searchError;
            logger.debug(`Search failed: ${searchError.message}`);
        }
        // 5. List all sites and match locally. Exact mode accepts only an exact name here too.
        try {
            const allSites = await graphClient.api('/sites').select(SITE_FIELDS).top(200).get();
            const sites = allSites?.value ?? [];
            if (sites.length > 0) {
                const match = exactNameMatch(sites, siteName);
                if (match)
                    return remember(match);
                const term = siteName.trim().toLowerCase();
                const fuzzy = sites.filter((site) => {
                    const displayName = site.displayName?.toLowerCase() || '';
                    const name = site.name?.toLowerCase() || '';
                    const webUrl = site.webUrl?.toLowerCase() || '';
                    return displayName.includes(term) || name.includes(term) || webUrl.includes(term) ||
                        displayName.split(/\s+/).includes(term) || name.split(/\s+/).includes(term);
                });
                if (candidates.length === 0)
                    candidates = fuzzy;
                if (!exact && fuzzy.length > 0) {
                    logger.info(`Found site by flexible matching: ${fuzzy[0].displayName} for search term: ${siteName}`);
                    return remember(fuzzy[0]);
                }
            }
        }
        catch (listError) {
            if (isAuthProblem(listError))
                throw listError;
            logger.debug(`List sites failed: ${listError.message}`);
        }
        if (exact) {
            const list = candidates.slice(0, 5).map(describe).join('; ');
            throw new Error(`No exact match for site '${siteName}'. Write operations require an exact site: pass the site ID, the full URL, ` +
                `or the exact display name.${list ? ` Candidates: ${list}` : ''}`);
        }
        throw new Error(`SharePoint site '${siteName}' not found. Try using the full URL like 'https://company.sharepoint.com/sites/sitename'`);
    }
    catch (error) {
        logger.error(`Error finding site ${siteName}:`, error);
        if (error.message?.includes('No exact match') || isAuthProblem(error))
            throw error;
        if (error.message?.includes('$count is not supported')) {
            throw new Error(`Failed to find site '${siteName}'. Try using the full SharePoint URL instead of just the site name.`);
        }
        throw new Error(`Failed to find SharePoint site '${siteName}': ${error.message}`);
    }
}
