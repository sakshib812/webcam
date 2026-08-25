export class WebglRendererVendorDetector {
    static scan() {
        const startTime = performance.now();
        let triggered = false;
        const evidence = {};
        try {
            const canvas = document.createElement('canvas');
            const gl = (canvas.getContext('webgl') || canvas.getContext('experimental-webgl'));
            if (gl) {
                const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                if (debugInfo) {
                    const vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) || '';
                    const renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) || '';
                    evidence['vendor'] = String(vendor);
                    evidence['renderer'] = String(renderer);
                    const lower = `${vendor} ${renderer}`.toLowerCase();
                    if (lower.includes('swiftshader') || lower.includes('llvmpipe') || lower.includes('mesa') || lower.includes('virtualbox')) {
                        triggered = true;
                        evidence['cloud_renderer'] = 'detected';
                    }
                }
            }
        }
        catch (e) {
            evidence['error'] = e.message || String(e);
        }
        const duration = Math.round(performance.now() - startTime);
        return {
            id: 'webgl_renderer_vendor_detector',
            name: 'WebGL Renderer & Vendor Subsystem Probe',
            triggered,
            severity: 3,
            category: 'hardware',
            event: 'webgl_renderer_cloud_anomaly',
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
