export class ScreenGeometryDetector {
    static scan() {
        const startTime = performance.now();
        let triggered = false;
        const evidence = {};
        if (typeof window !== 'undefined' && window.screen) {
            const scr = window.screen;
            evidence['width'] = String(scr.width);
            evidence['height'] = String(scr.height);
            evidence['colorDepth'] = String(scr.colorDepth);
            evidence['devicePixelRatio'] = String(window.devicePixelRatio || 1);
            if (scr.width === 1024 && scr.height === 768 && scr.colorDepth === 24) {
                evidence['headless_viewport_signature'] = 'detected';
            }
        }
        const duration = Math.round(performance.now() - startTime);
        return {
            id: 'screen_geometry_detector',
            name: 'Screen & Spatial Geometry Probe',
            triggered,
            severity: 2,
            category: 'hardware',
            event: 'screen_spatial_geometry_audit',
            confidence: 0.85,
            fpRiskTier: 'LOW',
            evasionDifficulty: 'MEDIUM',
            requiresConsent: false,
            status: triggered ? 'FAILED' : 'PASSED',
            executionTimeMs: duration,
            evidence
        };
    }
}
