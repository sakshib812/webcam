export class ErrorStackFormatDetector {
    static scan() {
        const startTime = performance.now();
        let triggered = false;
        const evidence = {};
        try {
            const stack = new Error().stack || '';
            const isV8Format = stack.includes('at ') || stack.includes('Error\n');
            const isSpiderMonkeyFormat = stack.includes('@');
            evidence['has_v8_stack'] = String(isV8Format);
            evidence['has_spidermonkey_stack'] = String(isSpiderMonkeyFormat);
            const ua = navigator.userAgent || '';
            const claimsChrome = ua.includes('Chrome') && !ua.includes('Edg');
            if (claimsChrome && isSpiderMonkeyFormat && !isV8Format) {
                triggered = true;
                evidence['engine_mismatch'] = 'claimed_chrome_but_firefox_spidermonkey_stack';
            }
        }
        catch {
            evidence['error'] = 'eval_failed';
        }
        return {
            id: 'error_stack_format_detector',
            name: 'Error Stack Trace V8 / SpiderMonkey Engine Format Detector',
            triggered,
            severity: 3,
            category: 'SPOOFING',
            event: 'ENGINE_FORMAT_MISMATCH',
            confidence: 0.95,
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
