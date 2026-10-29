/**
 * Emergency Control System
 *
 * Provides emergency kill switch and read-only mode capabilities
 * for instant security response to attacks or incidents
 */
import { logger } from './logger.js';
import path from 'path';
import { readStateFile, writeStateFile, resolveStateDir, UnsafeStateFileError } from './state-file.js';
export var EmergencyMode;
(function (EmergencyMode) {
    EmergencyMode["NORMAL"] = "normal";
    EmergencyMode["READONLY"] = "readonly";
    EmergencyMode["SHUTDOWN"] = "shutdown";
})(EmergencyMode || (EmergencyMode = {}));
const EMERGENCY_MODES = new Set(Object.values(EmergencyMode));
/** undefined when absent, null when present but not a parseable date. */
function optionalDate(value) {
    if (value === undefined || value === null)
        return undefined;
    if (typeof value !== 'string' && typeof value !== 'number')
        return null;
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date;
}
function optionalString(value) {
    if (value === undefined || value === null)
        return undefined;
    return typeof value === 'string' ? value : null;
}
/**
 * Rebuilds an EmergencyState from persisted JSON, copying only the documented fields.
 * Returns null for anything that does not match the schema, so a planted or corrupted file
 * can never inject a mode or an object into the running state.
 */
export function parsePersistedEmergencyState(raw) {
    let parsed;
    try {
        parsed = JSON.parse(raw);
    }
    catch {
        return null;
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed))
        return null;
    const record = parsed;
    if (typeof record.mode !== 'string' || !EMERGENCY_MODES.has(record.mode))
        return null;
    const activatedAt = optionalDate(record.activatedAt);
    const autoRevertAt = optionalDate(record.autoRevertAt);
    const reason = optionalString(record.reason);
    const activatedBy = optionalString(record.activatedBy);
    if (activatedAt === null || autoRevertAt === null || reason === null || activatedBy === null)
        return null;
    return { mode: record.mode, activatedAt, autoRevertAt, reason, activatedBy };
}
export class EmergencyControlSystem {
    static instance;
    currentState;
    stateFilePath;
    checkInterval = null;
    loaded;
    constructor() {
        // Initialize from environment or default to normal
        this.currentState = {
            mode: this.getInitialMode()
        };
        // Persist in a per-user private directory, never a world-writable one.
        this.stateFilePath = path.join(resolveStateDir(process.env.EMERGENCY_STATE_DIR, process.env.LOG_DIR), 'emergency-state.json');
        // Load persisted state. loadState never rejects; callers await ready() before trusting the mode.
        this.loaded = this.loadState();
        // Check for auto-revert every minute
        this.checkInterval = setInterval(() => {
            this.checkAutoRevert();
        }, 60000);
        this.checkInterval.unref?.();
        // Log initial state
        if (this.currentState.mode !== EmergencyMode.NORMAL) {
            logger.warn('EMERGENCY MODE ACTIVE', {
                mode: this.currentState.mode,
                reason: this.currentState.reason
            });
        }
        logger.info('Emergency Control System initialized', {
            mode: this.currentState.mode,
            stateFile: this.stateFilePath
        });
    }
    static getInstance() {
        if (!EmergencyControlSystem.instance) {
            EmergencyControlSystem.instance = new EmergencyControlSystem();
        }
        return EmergencyControlSystem.instance;
    }
    /** Resolves once persisted state has been read (or rejected). Await before the first checkAccess. */
    ready() {
        return this.loaded;
    }
    /**
     * Check if system should block the request
     * @param method HTTP method
     * @param path Request path
     * @returns Error message if blocked, null if allowed
     */
    checkAccess(method, path) {
        switch (this.currentState.mode) {
            case EmergencyMode.SHUTDOWN:
                // Block ALL requests
                logger.warn('Request blocked - Emergency shutdown active', {
                    method,
                    path,
                    reason: this.currentState.reason
                });
                return `System is in emergency shutdown mode. Reason: ${this.currentState.reason || 'Security incident'}`;
            case EmergencyMode.READONLY:
                // Only allow GET requests
                if (method.toUpperCase() !== 'GET') {
                    logger.warn('Write request blocked - Read-only mode active', {
                        method,
                        path,
                        reason: this.currentState.reason
                    });
                    return `System is in read-only mode. Only GET requests are allowed. Reason: ${this.currentState.reason || 'Maintenance'}`;
                }
                break;
            case EmergencyMode.NORMAL:
            default:
                // Normal operation
                return null;
        }
        return null;
    }
    /**
     * Activate emergency shutdown (blocks ALL requests)
     */
    async activateShutdown(reason, activatedBy, autoRevertMinutes) {
        this.currentState = {
            mode: EmergencyMode.SHUTDOWN,
            activatedAt: new Date(),
            reason,
            activatedBy,
            autoRevertAt: autoRevertMinutes
                ? new Date(Date.now() + autoRevertMinutes * 60 * 1000)
                : undefined
        };
        await this.saveState();
        // Critical audit log
        logger.audit('EMERGENCY_SHUTDOWN_ACTIVATED', {
            action: 'ACTIVATE_SHUTDOWN',
            result: 'SUCCESS',
            targetResource: 'system',
            metadata: {
                reason,
                activatedBy,
                autoRevertAt: this.currentState.autoRevertAt
            }
        });
        logger.error('🚨 EMERGENCY SHUTDOWN ACTIVATED 🚨', {
            reason,
            activatedBy,
            autoRevertMinutes
        });
        // Send alerts (would integrate with alerting system)
        this.sendEmergencyAlert('SHUTDOWN', reason);
    }
    /**
     * Activate read-only mode (blocks all write operations)
     */
    async activateReadOnly(reason, activatedBy, autoRevertMinutes) {
        this.currentState = {
            mode: EmergencyMode.READONLY,
            activatedAt: new Date(),
            reason,
            activatedBy,
            autoRevertAt: autoRevertMinutes
                ? new Date(Date.now() + autoRevertMinutes * 60 * 1000)
                : undefined
        };
        await this.saveState();
        logger.audit('EMERGENCY_READONLY_ACTIVATED', {
            action: 'ACTIVATE_READONLY',
            result: 'SUCCESS',
            targetResource: 'system',
            metadata: {
                reason,
                activatedBy,
                autoRevertAt: this.currentState.autoRevertAt
            }
        });
        logger.warn('⚠️ READ-ONLY MODE ACTIVATED ⚠️', {
            reason,
            activatedBy,
            autoRevertMinutes
        });
        this.sendEmergencyAlert('READONLY', reason);
    }
    /**
     * Deactivate emergency mode and return to normal
     */
    async deactivate(deactivatedBy) {
        const previousMode = this.currentState.mode;
        this.currentState = {
            mode: EmergencyMode.NORMAL
        };
        await this.saveState();
        logger.audit('EMERGENCY_MODE_DEACTIVATED', {
            action: 'DEACTIVATE',
            result: 'SUCCESS',
            targetResource: 'system',
            metadata: {
                previousMode,
                deactivatedBy
            }
        });
        logger.info('✅ Emergency mode deactivated - Normal operation resumed', {
            previousMode,
            deactivatedBy
        });
    }
    /**
     * Get current emergency status
     */
    getStatus() {
        return {
            ...this.currentState,
            isActive: this.currentState.mode !== EmergencyMode.NORMAL
        };
    }
    /**
     * Check if a specific operation is allowed
     */
    isOperationAllowed(operation) {
        switch (this.currentState.mode) {
            case EmergencyMode.SHUTDOWN:
                return false;
            case EmergencyMode.READONLY:
                // Allow read operations
                const readOperations = ['read', 'get', 'list', 'view', 'status', 'health'];
                return readOperations.some(op => operation.toLowerCase().includes(op));
            case EmergencyMode.NORMAL:
            default:
                return true;
        }
    }
    /**
     * Get initial mode from environment
     */
    getInitialMode() {
        if (process.env.EMERGENCY_SHUTDOWN === 'true') {
            logger.error('Starting in EMERGENCY SHUTDOWN mode from environment');
            return EmergencyMode.SHUTDOWN;
        }
        if (process.env.EMERGENCY_READONLY === 'true') {
            logger.warn('Starting in READ-ONLY mode from environment');
            return EmergencyMode.READONLY;
        }
        return EmergencyMode.NORMAL;
    }
    /**
     * Load persisted emergency state
     */
    async loadState() {
        let data;
        try {
            data = await readStateFile(this.stateFilePath);
        }
        catch (error) {
            if (error instanceof UnsafeStateFileError) {
                logger.error('Refusing to read emergency state file', { path: this.stateFilePath, reason: error.message });
            }
            else {
                logger.error('Error loading emergency state', error);
            }
            return;
        }
        if (data === null)
            return;
        const state = parsePersistedEmergencyState(data);
        if (!state) {
            logger.warn('Ignoring invalid emergency state file', { path: this.stateFilePath });
            return;
        }
        // Don't override environment settings on startup
        if (this.currentState.mode === EmergencyMode.NORMAL) {
            this.currentState = state;
            logger.info('Emergency state loaded from disk', {
                mode: this.currentState.mode,
                reason: this.currentState.reason
            });
        }
    }
    /**
     * Save emergency state to disk
     */
    async saveState() {
        try {
            await writeStateFile(this.stateFilePath, JSON.stringify(this.currentState, null, 2));
        }
        catch (error) {
            if (error instanceof UnsafeStateFileError) {
                logger.error('Refusing to write emergency state file', { path: this.stateFilePath, reason: error.message });
            }
            else {
                logger.error('Failed to save emergency state', error);
            }
        }
    }
    /**
     * Check if auto-revert time has been reached
     */
    checkAutoRevert() {
        if (this.currentState.autoRevertAt &&
            this.currentState.mode !== EmergencyMode.NORMAL) {
            if (new Date() >= this.currentState.autoRevertAt) {
                logger.info('Auto-reverting emergency mode', {
                    mode: this.currentState.mode,
                    autoRevertAt: this.currentState.autoRevertAt
                });
                this.deactivate('auto_revert').catch(err => {
                    logger.error('Failed to auto-revert emergency mode', err);
                });
            }
        }
    }
    /**
     * Send emergency alert (placeholder for integration)
     */
    sendEmergencyAlert(type, reason) {
        // This would integrate with alerting systems like:
        // - Email
        // - Slack
        // - PagerDuty
        // - Azure Monitor
        logger.error('EMERGENCY ALERT', {
            type,
            reason,
            timestamp: new Date().toISOString(),
            alertEmail: process.env.ALERT_EMAIL || 'not_configured'
        });
    }
    /**
     * Quick status check for health endpoint
     */
    isHealthy() {
        return this.currentState.mode === EmergencyMode.NORMAL;
    }
    /**
     * Get detailed metrics
     */
    getMetrics() {
        return {
            mode: this.currentState.mode,
            isActive: this.currentState.mode !== EmergencyMode.NORMAL,
            activatedAt: this.currentState.activatedAt,
            duration: this.currentState.activatedAt
                ? Date.now() - this.currentState.activatedAt.getTime()
                : 0,
            autoRevertAt: this.currentState.autoRevertAt,
            reason: this.currentState.reason
        };
    }
    /**
     * Cleanup on shutdown
     */
    destroy() {
        if (this.checkInterval) {
            clearInterval(this.checkInterval);
            this.checkInterval = null;
        }
    }
}
// Export singleton instance
export const emergencyControls = EmergencyControlSystem.getInstance();
