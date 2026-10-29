/**
 * Zero Trust Monitor - Level 0.5 Implementation
 *
 * This module implements comprehensive context logging and risk scoring
 * in REPORT-ONLY mode. It does not enforce any policies or block access.
 *
 * Purpose: Collect baseline data for 30 days before enabling enforcement
 * Risk Level: ZERO - No breaking changes, monitoring only
 */
import { logger } from './logger.js';
import crypto from 'crypto';
/**
 * Zero Trust Monitor for gradual implementation
 * Currently in REPORT-ONLY mode - logs but doesn't enforce
 */
/** Retention for baseline entries, by key prefix. Request counters are hourly buckets. */
const REQUEST_COUNTER_RETENTION_MS = 24 * 60 * 60 * 1000;
const HISTORY_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
export const DEFAULT_MAX_BASELINE_ENTRIES = 10000;
export class ZeroTrustMonitor {
    static instance;
    baselineData = new Map();
    maxBaselineEntries;
    reportOnlyMode = process.env.ZERO_TRUST_ENFORCE !== 'true';
    collectBaselineData = true;
    // Configurable thresholds (will be tuned based on baseline data)
    thresholds = {
        untrusted: 30,
        low: 50,
        medium: 70,
        high: 85,
        full: 95
    };
    constructor(options = {}) {
        this.maxBaselineEntries = options.maxBaselineEntries ?? DEFAULT_MAX_BASELINE_ENTRIES;
        logger.info('Zero Trust Monitor initialized in REPORT-ONLY mode (Level 0.5)');
        // Prune baseline data every hour: request counters are hourly buckets, so anything older
        // than a day is dead weight; operation and device history is kept for 30 days.
        setInterval(() => this.pruneBaseline(), 60 * 60 * 1000).unref?.();
    }
    static getInstance() {
        if (!ZeroTrustMonitor.instance) {
            ZeroTrustMonitor.instance = new ZeroTrustMonitor();
        }
        return ZeroTrustMonitor.instance;
    }
    /**
     * Collect context for Zero Trust evaluation
     * This is NON-BLOCKING and will not affect authentication flow
     */
    async collectContext(request) {
        const context = {
            requestTime: new Date(),
            apiPath: request.path,
            httpMethod: request.method,
            userAgent: request.headers?.['user-agent'],
            ipAddress: this.extractIpAddress(request),
            sessionId: this.generateSessionId(request),
            operationSensitivity: this.classifyOperationSensitivity(request.path, request.method)
        };
        // Extract user context if available
        if (request.user) {
            context.userId = request.user.id;
            context.userPrincipalName = request.user.upn;
            context.tenantId = request.user.tid;
        }
        // Device fingerprinting (basic implementation)
        context.deviceFingerprint = this.generateDeviceFingerprint(request);
        // Add behavioral signals
        await this.addBehavioralContext(context);
        // Log context for baseline collection
        if (this.collectBaselineData) {
            this.storeBaselineData(context);
        }
        return context;
    }
    /**
     * Calculate trust score based on context
     * REPORT-ONLY: This will not block any requests
     */
    async calculateTrustScore(context) {
        const signals = [];
        let baseScore = 100;
        // Check various risk signals
        // 1. Missing MFA (medium risk)
        if (!context.mfaCompleted && context.operationSensitivity !== 'low') {
            signals.push({
                signal: 'missing_mfa',
                weight: -15,
                severity: 'medium',
                description: 'Multi-factor authentication not completed'
            });
            baseScore -= 15;
        }
        // 2. Unknown device (low risk)
        if (!this.isKnownDevice(context.deviceFingerprint)) {
            signals.push({
                signal: 'unknown_device',
                weight: -10,
                severity: 'low',
                description: 'Request from unrecognized device'
            });
            baseScore -= 10;
        }
        // 3. Suspicious IP (high risk)
        if (context.ipReputation === 'suspicious' || context.ipReputation === 'malicious') {
            signals.push({
                signal: 'suspicious_ip',
                weight: -30,
                severity: 'high',
                description: `IP address flagged as ${context.ipReputation}`
            });
            baseScore -= 30;
        }
        // 4. Unusual time (info only)
        if (context.unusualTime) {
            signals.push({
                signal: 'unusual_time',
                weight: -5,
                severity: 'info',
                description: 'Access at unusual time for this user'
            });
            baseScore -= 5;
        }
        // 5. High request rate (medium risk)
        if (context.requestsLastHour && context.requestsLastHour > 1000) {
            signals.push({
                signal: 'high_request_rate',
                weight: -20,
                severity: 'medium',
                description: `High request rate: ${context.requestsLastHour} requests in last hour`
            });
            baseScore -= 20;
        }
        // 6. Sensitive operation without device compliance (high risk)
        if (context.operationSensitivity === 'critical' && !context.deviceCompliant) {
            signals.push({
                signal: 'unmanaged_device_sensitive_op',
                weight: -25,
                severity: 'high',
                description: 'Critical operation from non-compliant device'
            });
            baseScore -= 25;
        }
        // 7. First time operation (info)
        if (context.firstTimeOperation) {
            signals.push({
                signal: 'first_time_operation',
                weight: -5,
                severity: 'info',
                description: 'User performing this operation for the first time'
            });
            baseScore -= 5;
        }
        // 8. Token age (low risk if old)
        if (context.tokenAge && context.tokenAge > 8 * 60 * 60 * 1000) { // 8 hours
            signals.push({
                signal: 'stale_token',
                weight: -10,
                severity: 'low',
                description: 'Authentication token older than 8 hours'
            });
            baseScore -= 10;
        }
        // Ensure score stays within bounds
        const finalScore = Math.max(0, Math.min(100, baseScore));
        // Determine trust level
        let level;
        if (finalScore >= this.thresholds.full)
            level = 'full';
        else if (finalScore >= this.thresholds.high)
            level = 'high';
        else if (finalScore >= this.thresholds.medium)
            level = 'medium';
        else if (finalScore >= this.thresholds.low)
            level = 'low';
        else
            level = 'untrusted';
        // Recommendation (not enforced in report-only mode)
        let recommendation;
        if (finalScore >= this.thresholds.medium) {
            recommendation = 'allow';
        }
        else if (finalScore >= this.thresholds.low) {
            recommendation = 'challenge'; // Would require MFA or additional verification
        }
        else {
            recommendation = 'deny'; // Would block in enforcement mode
        }
        const trustScore = {
            score: finalScore,
            level,
            signals,
            recommendation,
            reportOnly: true, // Always true in Level 0.5
            timestamp: new Date()
        };
        // Log the trust evaluation (report-only)
        this.logTrustEvaluation(context, trustScore);
        return trustScore;
    }
    /**
     * Log trust evaluation for analysis and baseline building
     */
    logTrustEvaluation(context, score) {
        const logEntry = {
            mode: 'REPORT_ONLY',
            timestamp: new Date().toISOString(),
            user: context.userId || 'anonymous',
            operation: `${context.httpMethod} ${context.apiPath}`,
            trustScore: score.score,
            trustLevel: score.level,
            recommendation: score.recommendation,
            wouldBlock: score.recommendation === 'deny',
            wouldChallenge: score.recommendation === 'challenge',
            signals: score.signals.map(s => ({
                signal: s.signal,
                severity: s.severity,
                impact: s.weight
            })),
            context: {
                device: context.deviceFingerprint?.substring(0, 8),
                ip: this.hashIp(context.ipAddress),
                sensitivity: context.operationSensitivity,
                mfa: context.mfaCompleted
            }
        };
        // Log to audit system
        logger.audit('ZERO_TRUST_EVALUATION', {
            action: 'EVALUATE',
            result: 'SUCCESS', // Always SUCCESS in report-only mode
            targetResource: context.apiPath,
            metadata: logEntry
        });
        // Log warning if would have blocked
        if (score.recommendation === 'deny') {
            logger.warn('Zero Trust would DENY this request (report-only mode)', logEntry);
        }
        else if (score.recommendation === 'challenge') {
            logger.info('Zero Trust would CHALLENGE this request (report-only mode)', logEntry);
        }
    }
    /**
     * Helper method to extract IP address
     */
    extractIpAddress(request) {
        return request.headers?.['x-forwarded-for']?.split(',')[0] ||
            request.headers?.['x-real-ip'] ||
            request.connection?.remoteAddress ||
            'unknown';
    }
    /**
     * Generate device fingerprint (basic implementation)
     */
    generateDeviceFingerprint(request) {
        const components = [
            request.headers?.['user-agent'] || '',
            request.headers?.['accept-language'] || '',
            request.headers?.['accept-encoding'] || '',
            // Add more device signals as available
        ];
        return crypto
            .createHash('sha256')
            .update(components.join('|'))
            .digest('hex');
    }
    /**
     * Generate session identifier
     */
    generateSessionId(request) {
        const components = [
            request.user?.id || 'anonymous',
            this.extractIpAddress(request),
            request.headers?.['user-agent'] || '',
            new Date().toISOString().split('T')[0] // Daily rotation
        ];
        return crypto
            .createHash('sha256')
            .update(components.join('|'))
            .digest('hex')
            .substring(0, 16);
    }
    /**
     * Classify operation sensitivity
     */
    classifyOperationSensitivity(path, method) {
        if (!path || !method)
            return 'low';
        // Critical operations
        if (path.includes('/roleManagement') ||
            path.includes('/privilegedAccess') ||
            path.includes('/applications') ||
            (method === 'DELETE' && path.includes('/users'))) {
            return 'critical';
        }
        // High sensitivity
        if (path.includes('/users') && (method === 'PATCH' || method === 'PUT') ||
            path.includes('/groups') && method !== 'GET' ||
            path.includes('/policies')) {
            return 'high';
        }
        // Medium sensitivity
        if (method !== 'GET' || path.includes('/audit')) {
            return 'medium';
        }
        return 'low';
    }
    /**
     * Check if device is known (from baseline)
     */
    isKnownDevice(fingerprint) {
        if (!fingerprint)
            return false;
        // Check baseline data for this device
        const deviceData = this.baselineData.get(`device:${fingerprint}`);
        return deviceData && deviceData.seenCount > 5; // Seen at least 5 times
    }
    /**
     * Add behavioral context
     */
    async addBehavioralContext(context) {
        const userId = context.userId || 'anonymous';
        // Check request rate
        const requestKey = `requests:${userId}:${new Date().getHours()}`;
        const requests = this.baselineData.get(requestKey);
        context.requestsLastHour = requests?.count ?? 0;
        // Check if unusual time
        const hourlyPattern = this.baselineData.get(`pattern:${userId}:hourly`) || {};
        const currentHour = new Date().getHours();
        context.unusualTime = hourlyPattern[currentHour] < 0.01; // Less than 1% of requests at this time
        // Check if first time operation
        const operationKey = `operation:${userId}:${context.httpMethod}:${context.apiPath}`;
        context.firstTimeOperation = !this.baselineData.has(operationKey);
    }
    /**
     * Store baseline data for pattern learning
     */
    storeBaselineData(context) {
        const userId = context.userId || 'anonymous';
        const hour = new Date().getHours();
        // Track device
        if (context.deviceFingerprint) {
            const deviceKey = `device:${context.deviceFingerprint}`;
            const deviceData = this.baselineData.get(deviceKey) || { seenCount: 0, firstSeen: new Date() };
            deviceData.seenCount++;
            deviceData.lastSeen = new Date();
            this.baselineData.set(deviceKey, deviceData);
        }
        // Track request patterns. The bucket carries its own timestamp so pruning can age it out.
        const requestKey = `requests:${userId}:${hour}`;
        const requests = this.baselineData.get(requestKey);
        const now = Date.now();
        this.baselineData.set(requestKey, {
            count: (requests?.count ?? 0) + 1,
            timestamp: now
        });
        // Track operation patterns
        const operationKey = `operation:${userId}:${context.httpMethod}:${context.apiPath}`;
        this.baselineData.set(operationKey, new Date(now));
        // Track hourly patterns
        const patternKey = `pattern:${userId}:hourly`;
        const pattern = this.baselineData.get(patternKey) || {};
        pattern[hour] = (pattern[hour] || 0) + 1;
        pattern.lastSeen = now;
        this.baselineData.set(patternKey, pattern);
        this.enforceBaselineBound();
    }
    /** Keeps the baseline map at or under its bound by dropping the oldest-inserted entries. */
    enforceBaselineBound() {
        while (this.baselineData.size > this.maxBaselineEntries) {
            const oldest = this.baselineData.keys().next().value;
            if (oldest === undefined)
                break;
            this.baselineData.delete(oldest);
        }
    }
    /**
     * Hash IP for privacy
     */
    hashIp(ip) {
        if (!ip)
            return 'unknown';
        return crypto
            .createHash('sha256')
            .update(ip)
            .digest('hex')
            .substring(0, 8);
    }
    /**
     * Drops baseline entries past their retention. Returns how many were removed.
     * `now` is injectable for tests.
     */
    pruneBaseline(now = Date.now()) {
        let removed = 0;
        for (const [key, value] of this.baselineData.entries()) {
            const lastSeen = this.entryTimestamp(key, value);
            const retention = key.startsWith('requests:') ? REQUEST_COUNTER_RETENTION_MS : HISTORY_RETENTION_MS;
            if (lastSeen === undefined || now - lastSeen > retention) {
                this.baselineData.delete(key);
                removed++;
            }
        }
        logger.info(`Zero Trust Monitor: pruned ${removed} baseline entries, current size: ${this.baselineData.size}`);
        return removed;
    }
    /** The last-activity time of a baseline entry as epoch ms, or undefined when it cannot be dated. */
    entryTimestamp(key, value) {
        if (value instanceof Date)
            return value.getTime(); // operation:*
        if (typeof value?.timestamp === 'number')
            return value.timestamp; // requests:*
        if (value?.lastSeen instanceof Date)
            return value.lastSeen.getTime(); // device:*
        if (typeof value?.lastSeen === 'number')
            return value.lastSeen; // pattern:*
        return undefined;
    }
    /**
     * Get baseline statistics (for monitoring)
     */
    getBaselineStats() {
        return {
            mode: 'REPORT_ONLY',
            level: 0.5,
            baselineDataPoints: this.baselineData.size,
            maxBaselineEntries: this.maxBaselineEntries,
            collectingBaseline: this.collectBaselineData,
            reportOnlyMode: this.reportOnlyMode,
            thresholds: this.thresholds
        };
    }
    /**
     * Export baseline data for analysis
     */
    exportBaselineData() {
        const summary = {
            exportTime: new Date().toISOString(),
            dataPoints: this.baselineData.size,
            devices: 0,
            users: new Set(),
            operations: new Set(),
            patterns: {}
        };
        for (const [key, value] of this.baselineData.entries()) {
            if (key.startsWith('device:'))
                summary.devices++;
            if (key.startsWith('operation:')) {
                const parts = key.split(':');
                summary.users.add(parts[1]);
                summary.operations.add(`${parts[2]} ${parts[3]}`);
            }
        }
        return {
            ...summary,
            uniqueUsers: summary.users.size,
            uniqueOperations: summary.operations.size
        };
    }
}
// Export singleton instance
export const zeroTrustMonitor = ZeroTrustMonitor.getInstance();
