export class TelemetrySerializer {
    static generateDeviceIdHash() {
        if (typeof window === 'undefined' || typeof navigator === 'undefined') {
            return 'dev_web_node_test_01';
        }
        const nav = navigator;
        const rawStr = [
            nav.userAgent || '',
            nav.language || '',
            nav.hardwareConcurrency || 4,
            window.screen ? `${window.screen.width}x${window.screen.height}` : '1024x768',
            new Date().getTimezoneOffset()
        ].join('|');
        let hash = 0;
        for (let i = 0; i < rawStr.length; i++) {
            const char = rawStr.charCodeAt(i);
            hash = (hash << 5) - hash + char;
            hash |= 0;
        }
        return `dev_web_${Math.abs(hash).toString(16)}`;
    }
    static formatOsVersion() {
        if (typeof navigator === 'undefined' || !navigator.userAgent) {
            return 'NodeJS 22';
        }
        return navigator.userAgent;
    }
    static createReport(items, tenantId, appId) {
        items.forEach(item => {
            if (!item.status) {
                item.status = item.triggered ? 'FAILED' : 'PASSED';
            }
            if (!item.name) {
                item.name = item.id;
            }
            if (item.confidence === undefined) {
                item.confidence = 0.85;
            }
            if (!item.fpRiskTier) {
                item.fpRiskTier = 'LOW';
            }
            if (!item.evasionDifficulty) {
                item.evasionDifficulty = 'MEDIUM';
            }
        });
        const failedItems = items.filter(i => i.triggered || i.status === 'FAILED');
        const failedCount = failedItems.length;
        const passedCount = items.length - failedCount;
        // Calculate dynamic risk score based on confidence-weighted severities
        const confidenceWeightedSum = failedItems.reduce((acc, item) => {
            const weight = item.confidence !== undefined ? item.confidence : 0.85;
            return acc + (item.severity || 1) * weight;
        }, 0);
        const rawRiskScore = Math.min(100, Math.round(confidenceWeightedSum * 1.2));
        const riskScore = failedCount > 0 ? Math.max(25, rawRiskScore) : 0;
        let riskTier = 'LOW';
        if (riskScore >= 75) {
            riskTier = 'CRITICAL';
        }
        else if (riskScore >= 50) {
            riskTier = 'HIGH';
        }
        else if (riskScore >= 25) {
            riskTier = 'MEDIUM';
        }
        const timestamp = Date.now();
        const deviceIdHash = TelemetrySerializer.generateDeviceIdHash();
        const osVersionStr = TelemetrySerializer.formatOsVersion();
        return {
            scan_id: `scan_web_${timestamp}_${Math.floor(Math.random() * 1000)}`,
            device_id_hash: deviceIdHash,
            session_id: `sess_web_${timestamp}`,
            os_name: 'Web',
            os_version: osVersionStr,
            app_id: appId || 'app_web_portal_prod',
            app_version: '1.0.0',
            sdk_version: '1.0.0',
            verdict: failedCount > 0 ? 'BLOCKED' : 'SECURE',
            risk_score: riskScore,
            risk_tier: riskTier,
            decision_action: failedCount > 0 ? 'BLOCK' : 'ALLOW',
            total_detectors: items.length,
            passed: passedCount,
            failed: failedCount,
            tenant_id: tenantId || 'TEN-ENTERPRISE-01',
            environment: 'web',
            items
        };
    }
}
