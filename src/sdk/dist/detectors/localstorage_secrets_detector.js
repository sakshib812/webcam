export class LocalstorageSecretsDetector {
    static scan() {
        const startTime = performance.now();
        let triggered = false;
        const evidence = {};
        try {
            if (typeof localStorage !== 'undefined') {
                const sensitiveKeys = [];
                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i) || '';
                    const lowerKey = key.toLowerCase();
                    if (lowerKey.includes('password') || lowerKey.includes('secret') || lowerKey.includes('private_key') || lowerKey.includes('ssn') || lowerKey.includes('credit_card')) {
                        sensitiveKeys.push(key);
                    }
                }
                if (sensitiveKeys.length > 0) {
                    triggered = true;
                    evidence['plaintext_sensitive_keys'] = sensitiveKeys.join(',');
                }
            }
        }
        catch (e) {
            evidence['error'] = e.message || String(e);
        }
        const duration = Math.round(performance.now() - startTime);
        return {
            id: 'localstorage_secrets_detector',
            name: 'localStorage Plaintext Sensitive Data Scanner',
            triggered,
            severity: 3,
            category: 'storage',
            event: 'localstorage_plaintext_secrets',
            confidence: 0.90,
            fpRiskTier: 'LOW',
            evasionDifficulty: 'MEDIUM',
            requiresConsent: false,
            status: triggered ? 'FAILED' : 'PASSED',
            executionTimeMs: duration,
            evidence
        };
    }
}
