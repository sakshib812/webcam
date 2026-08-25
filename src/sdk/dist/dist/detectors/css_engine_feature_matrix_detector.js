export class CssEngineFeatureMatrixDetector {
    static scan() {
        const startTime = performance.now();
        let triggered = false;
        const evidence = {};
        try {
            if (typeof CSS !== 'undefined' && typeof CSS.supports === 'function') {
                const backdropFilter = CSS.supports('backdrop-filter', 'blur(5px)');
                const grid = CSS.supports('display', 'grid');
                const container = CSS.supports('container-type', 'inline-size');
                evidence['backdrop_filter'] = String(backdropFilter);
                evidence['display_grid'] = String(grid);
                evidence['container_queries'] = String(container);
            }
            else {
                evidence['css_supports'] = 'unsupported';
            }
        }
        catch {
            evidence['error'] = 'eval_failed';
        }
        return {
            id: 'css_engine_feature_matrix_detector',
            name: 'CSS.supports Rendering Engine Feature Matrix Detector',
            triggered,
            severity: 2,
            category: 'SPOOFING',
            event: 'CSS_ENGINE_MATRIX_PROBED',
            confidence: 0.85,
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
