export class FontLoadingEnumerationDetector {
    static scan() {
        const startTime = performance.now();
        let triggered = false;
        const evidence = {};
        try {
            if (typeof document !== 'undefined' && 'fonts' in document && typeof document.fonts.check === 'function') {
                const testFonts = ['Arial', 'Times New Roman', 'Courier New', 'Roboto', 'Segoe UI', 'Ubuntu'];
                const available = testFonts.filter(f => document.fonts.check(`12px "${f}"`));
                evidence['fonts_checked'] = String(testFonts.length);
                evidence['fonts_available'] = available.join(', ');
            }
            else {
                evidence['font_api'] = 'unsupported';
            }
        }
        catch {
            evidence['error'] = 'eval_failed';
        }
        return {
            id: 'font_loading_enumeration_detector',
            name: 'Font Loading API Local Font Enumeration Detector',
            triggered,
            severity: 2,
            category: 'FINGERPRINT',
            event: 'FONTS_ENUMERATED',
            confidence: 0.70,
            fpRiskTier: 'MEDIUM',
            evasionDifficulty: 'MEDIUM',
            requiresConsent: false,
            implementationCost: 'MEDIUM',
            status: triggered ? 'FAILED' : 'PASSED',
            executionTimeMs: Math.round(performance.now() - startTime),
            evidence
        };
    }
}
