export class IntlLocaleFingerprintDetector {
    static scan() {
        const startTime = performance.now();
        let triggered = false;
        const evidence = {};
        try {
            if (typeof Intl !== 'undefined' && Intl.DateTimeFormat) {
                const options = Intl.DateTimeFormat().resolvedOptions();
                evidence['timeZone'] = options.timeZone || 'unknown';
                evidence['locale'] = options.locale || 'unknown';
                evidence['calendar'] = options.calendar || 'unknown';
                evidence['numberingSystem'] = options.numberingSystem || 'unknown';
            }
        }
        catch {
            evidence['error'] = 'eval_failed';
        }
        return {
            id: 'intl_locale_fingerprint_detector',
            name: 'Intl & Locale Timezone Fingerprint Detector',
            triggered,
            severity: 2,
            category: 'FINGERPRINT',
            event: 'INTL_LOCALE_PROBED',
            confidence: 0.85,
            fpRiskTier: 'LOW',
            evasionDifficulty: 'MEDIUM',
            requiresConsent: false,
            implementationCost: 'LOW',
            status: triggered ? 'FAILED' : 'PASSED',
            executionTimeMs: Math.round(performance.now() - startTime),
            evidence
        };
    }
}
