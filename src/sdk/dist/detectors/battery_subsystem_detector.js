export class BatterySubsystemDetector {
    static scan() {
        const startTime = performance.now();
        const evidence = {};
        const nav = navigator;
        if (typeof nav !== 'undefined' && typeof nav.getBattery === 'function') {
            evidence['get_battery_api'] = 'supported';
        }
        else {
            evidence['get_battery_api'] = 'deprecated_or_unsupported';
        }
        const duration = Math.round(performance.now() - startTime);
        return {
            id: 'battery_subsystem_detector',
            name: 'Battery Status Subsystem Probe (Legacy Fallback)',
            triggered: false,
            severity: 1,
            category: 'hardware',
            event: 'battery_legacy_fallback',
            confidence: 0.20,
            fpRiskTier: 'HIGH',
            evasionDifficulty: 'LOW',
            requiresConsent: false,
            status: 'PASSED',
            executionTimeMs: duration,
            evidence
        };
    }
}
