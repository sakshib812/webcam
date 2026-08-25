export class InputPointerMediaQueryDetector {
    static scan() {
        const startTime = performance.now();
        let triggered = false;
        const evidence = {};
        try {
            if (typeof window !== 'undefined' && window.matchMedia) {
                const pointerCoarse = window.matchMedia('(pointer: coarse)').matches;
                const hoverHover = window.matchMedia('(hover: hover)').matches;
                const anyPointerFine = window.matchMedia('(any-pointer: fine)').matches;
                evidence['pointer_coarse'] = String(pointerCoarse);
                evidence['hover_hover'] = String(hoverHover);
                evidence['any_pointer_fine'] = String(anyPointerFine);
                // Anomaly check: Claims mobile UA but has fine pointer + hover capability without coarse touch pointer
                const ua = navigator.userAgent || '';
                const claimsMobileUA = /iPhone|Android.*Mobile/i.test(ua);
                if (claimsMobileUA && !pointerCoarse && hoverHover) {
                    triggered = true;
                    evidence['pointer_ua_anomaly'] = 'mobile_ua_with_desktop_mouse_pointer';
                }
            }
        }
        catch {
            evidence['error'] = 'eval_failed';
        }
        return {
            id: 'input_pointer_media_query_detector',
            name: 'Pointer & Hover Input Media Query Detector',
            triggered,
            severity: 3,
            category: 'SPOOFING',
            event: 'POINTER_UA_MISMATCH',
            confidence: 0.90,
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
