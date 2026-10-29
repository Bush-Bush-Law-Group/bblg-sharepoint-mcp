/**
 * Private persistence for the server's small JSON state files (emergency mode, revocation list).
 *
 * The threat is another local user, not a remote one: a world-writable directory such as /tmp lets
 * anyone plant a state file the server will trust, or a symlink the server will write through. So:
 *  - the default location is inside the current user's home, created 0o700;
 *  - a state file is only read or replaced when it is a regular file owned by this user, never a
 *    symlink, and is opened O_NOFOLLOW where the platform supports it;
 *  - writes go to a fresh, exclusively created 0o600 temp file that is renamed into place, so a
 *    reader never sees a partial file and a pre-planted path is never followed.
 * Content validation is the caller's job: this module returns raw text.
 */
import fs from 'fs/promises';
import { randomBytes } from 'crypto';
import { homedir } from 'os';
import path from 'path';
export const DEFAULT_STATE_DIR = path.join(homedir(), '.sharepoint-mcp', 'state');
/** The first configured directory, falling back to the private per-user default. */
export function resolveStateDir(...configured) {
    return configured.find(dir => typeof dir === 'string' && dir.trim() !== '') ?? DEFAULT_STATE_DIR;
}
/** Raised when a state path is a symlink, a non-regular file, or belongs to another user. */
export class UnsafeStateFileError extends Error {
    filePath;
    constructor(filePath, reason) {
        super(`${filePath}: ${reason}`);
        this.filePath = filePath;
        this.name = 'UnsafeStateFileError';
    }
}
function assertOwnedRegularFile(filePath, stat) {
    if (stat.isSymbolicLink()) {
        throw new UnsafeStateFileError(filePath, 'is a symbolic link');
    }
    if (!stat.isFile()) {
        throw new UnsafeStateFileError(filePath, 'is not a regular file');
    }
    const uid = process.getuid?.();
    if (uid !== undefined && stat.uid !== uid) {
        throw new UnsafeStateFileError(filePath, `is owned by uid ${stat.uid}, not the current user (uid ${uid})`);
    }
}
/**
 * Returns true when a safe file exists at the path, false when nothing exists there.
 * Throws UnsafeStateFileError for anything that must not be used.
 */
async function checkExisting(filePath) {
    let stat;
    try {
        stat = await fs.lstat(filePath);
    }
    catch (error) {
        if (error?.code === 'ENOENT')
            return false;
        throw error;
    }
    assertOwnedRegularFile(filePath, stat);
    return true;
}
/** Reads a state file, or returns null when none exists. Refuses symlinks and foreign files. */
export async function readStateFile(filePath) {
    if (!(await checkExisting(filePath)))
        return null;
    // Re-check on the open handle so the lstat above cannot be raced by a swap.
    const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0);
    let handle;
    try {
        handle = await fs.open(filePath, flags);
    }
    catch (error) {
        if (error?.code === 'ELOOP')
            throw new UnsafeStateFileError(filePath, 'is a symbolic link');
        if (error?.code === 'ENOENT')
            return null;
        throw error;
    }
    try {
        assertOwnedRegularFile(filePath, await handle.stat());
        return await handle.readFile('utf8');
    }
    finally {
        await handle.close();
    }
}
/**
 * Atomically replaces a state file with `contents`, creating the directory 0o700 if needed.
 * Refuses to replace a symlink or a file owned by someone else.
 */
export async function writeStateFile(filePath, contents) {
    const dir = path.dirname(filePath);
    await fs.mkdir(dir, { recursive: true, mode: 0o700 });
    await checkExisting(filePath);
    const tempPath = path.join(dir, `.${path.basename(filePath)}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`);
    // 'wx' fails if the temp path already exists, so a pre-planted file or link is never reused.
    const handle = await fs.open(tempPath, 'wx', 0o600);
    try {
        try {
            await handle.writeFile(contents, 'utf8');
            await handle.sync();
        }
        finally {
            await handle.close();
        }
        await fs.rename(tempPath, filePath);
    }
    catch (error) {
        await fs.unlink(tempPath).catch(() => undefined);
        throw error;
    }
}
