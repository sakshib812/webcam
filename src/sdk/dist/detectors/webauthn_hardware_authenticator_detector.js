export class WebAuthnHardwareAuthenticatorDetector {
    static scan() {
        const startTime = performance.now();
        let triggered = false;
        const evidence = {};
        try {
            if (typeof window !== 'undefined' && 'PublicKeyCredential' in window) {
                evidence['webauthn_supported'] = 'true';
                if (typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function') {
                    evidence['platform_authenticator_api'] = 'supported';
                }
            }
            else {
                evidence['webauthn_supported'] = 'false';
            }
        }
        catch {
            evidence['error'] = 'eval_failed';
        }
        return {
            id: 'webauthn_hardware_authenticator_detector',
            name: 'WebAuthn Platform Authenticator Hardware Detector',
            triggered,
            severity: 2,
            category: 'HARDWARE',
            event: 'WEBAUTHN_HARDWARE_PROBED',
            confidence: 0.90,
            fpRiskTier: 'LOW',
            evasionDifficulty: 'HIGH',
            requiresConsent: false,
            implementationCost: 'LOW',
            status: triggered ? 'FAILED' : 'PASSED',
            executionTimeMs: Math.round(performance.now() - startTime),
            evidence
        };
    }
}
