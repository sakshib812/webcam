export class WebgpuSubsystemDetector {
    static scan() {
        const startTime = performance.now();
        let triggered = false;
        const evidence = {};
        const nav = navigator;
        if (nav.gpu) {
            evidence['webgpu_available'] = 'true';
        }
        else {
            evidence['webgpu_available'] = 'false';
        }
        const duration = Math.round(performance.now() - startTime);
        return {
            id: 'webgpu_subsystem_detector',
            name: 'WebGPU Hardware Compute Subsystem Probe',
            triggered,
            severity: 2,
            category: 'hardware',
            event: 'webgpu_subsystem_audit',
            confidence: 0.85,
            fpRiskTier: 'LOW',
            evasionDifficulty: 'HIGH',
            requiresConsent: false,
            status: 'PASSED',
            executionTimeMs: duration,
            evidence
        };
    }
}
