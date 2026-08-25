export interface DetectorItem {
    id: string;
    triggered: boolean;
    severity: number;
    category: string;
    event: string;
    confidence?: number;
    fpRiskTier?: 'LOW' | 'MEDIUM' | 'HIGH';
    evasionDifficulty?: 'LOW' | 'MEDIUM' | 'HIGH';
    requiresConsent?: boolean;
    implementationCost?: 'LOW' | 'MEDIUM' | 'HIGH';
    status?: 'PASSED' | 'FAILED' | 'INCONCLUSIVE' | 'SKIPPED_NO_CONSENT';
    name?: string;
    executionTimeMs?: number;
    evidence?: Record<string, any>;
}
export interface SecurityAuditReport {
    scan_id: string;
    device_id_hash: string;
    session_id: string;
    os_name: string;
    os_version: string;
    app_id: string;
    app_version: string;
    sdk_version: string;
    verdict: 'SECURE' | 'BLOCKED';
    risk_score: number;
    risk_tier: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    decision_action: 'ALLOW' | 'BLOCK';
    total_detectors: number;
    passed: number;
    failed: number;
    tenant_id: string;
    environment: string;
    items: DetectorItem[];
}
export declare class TelemetrySerializer {
    private static generateDeviceIdHash;
    private static formatOsVersion;
    static createReport(items: DetectorItem[], tenantId?: string, appId?: string): SecurityAuditReport;
}
