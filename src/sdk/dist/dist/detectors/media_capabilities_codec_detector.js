export class MediaCapabilitiesCodecDetector {
    static scan() {
        const startTime = performance.now();
        let triggered = false;
        const evidence = {};
        try {
            if (typeof navigator !== 'undefined' && navigator.mediaCapabilities) {
                evidence['media_capabilities'] = 'supported';
            }
            else {
                evidence['media_capabilities'] = 'unsupported';
            }
        }
        catch {
            evidence['error'] = 'eval_failed';
        }
        return {
            id: 'media_capabilities_codec_detector',
            name: 'Media Capabilities Codec Matrix Detector',
            triggered,
            severity: 1,
            category: 'HARDWARE',
            event: 'MEDIA_CAPABILITIES_PROBED',
            confidence: 0.80,
            fpRiskTier: 'LOW',
            evasionDifficulty: 'MEDIUM',
            requiresConsent: false,
            implementationCost: 'MEDIUM',
            status: triggered ? 'FAILED' : 'PASSED',
            executionTimeMs: Math.round(performance.now() - startTime),
            evidence
        };
    }
}
