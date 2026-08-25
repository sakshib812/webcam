export class HardwareTopologyDetector {
    static scan() {
        const startTime = performance.now();
        let triggered = false;
        const evidence = {};
        if (typeof navigator !== 'undefined') {
            const nav = navigator;
            evidence['hardwareConcurrency'] = String(nav.hardwareConcurrency || 4);
            if (nav.deviceMemory) {
                evidence['deviceMemory'] = String(nav.deviceMemory);
            }
            if (nav.hardwareConcurrency === 1) {
                triggered = true;
                evidence['single_core_container_anomaly'] = 'detected';
            }
        }
        const duration = Math.round(performance.now() - startTime);
        return {
            id: 'hardware_topology_detector',
            name: 'Client Hardware Memory & Thread Topology Probe',
            triggered,
            severity: 2,
            category: 'hardware',
            event: 'hardware_topology_audit',
            confidence: 0.80,
            fpRiskTier: 'LOW',
            evasionDifficulty: 'MEDIUM',
            requiresConsent: false,
            status: triggered ? 'FAILED' : 'PASSED',
            executionTimeMs: duration,
            evidence
        };
    }
}
