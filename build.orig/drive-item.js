/**
 * Drive item selection and presentation shared by the sharepoint-site-files listings.
 *
 * `@microsoft.graph.downloadUrl` is a short-lived, pre-authenticated URL: anyone holding it can
 * fetch the file without a token. It is therefore never selected or returned by a listing, only
 * by the explicit get_content operation.
 */
export const DRIVE_ITEM_LIST_SELECT = 'id,name,size,createdDateTime,lastModifiedDateTime,webUrl,file,folder,createdBy,lastModifiedBy,parentReference,shared';
export const DRIVE_ITEM_CONTENT_SELECT = 'id,name,size,@microsoft.graph.downloadUrl';
export function formatFileSize(bytes) {
    if (bytes === 0)
        return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}
/** The compact file/folder shape returned by listings. Never includes the download URL. */
export function formatDriveItem(item, options = {}) {
    const result = {
        id: item.id,
        name: item.name,
        type: item.folder ? 'folder' : 'file',
        size: item.size || 0,
        sizeFormatted: formatFileSize(item.size || 0),
        createdDateTime: item.createdDateTime,
        lastModifiedDateTime: item.lastModifiedDateTime,
        webUrl: item.webUrl
    };
    if (item.createdBy?.user) {
        result.createdBy = item.createdBy.user.displayName || item.createdBy.user.email;
    }
    if (item.lastModifiedBy?.user) {
        result.lastModifiedBy = item.lastModifiedBy.user.displayName || item.lastModifiedBy.user.email;
    }
    if (item.file) {
        result.mimeType = item.file.mimeType;
        result.fileExtension = item.name?.split('.').pop()?.toLowerCase();
    }
    if (item.folder) {
        result.childCount = item.folder.childCount;
    }
    if (item.shared) {
        result.isShared = true;
        result.sharedInfo = item.shared;
    }
    if (options.includePermissions && item.permissions) {
        result.permissions = item.permissions;
    }
    if (item.parentReference) {
        result.path = item.parentReference.path?.replace('/drive/root:', '') || '/';
    }
    return result;
}
