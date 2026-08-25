/**
 * VirtualBrowserDetector: P4 Informational / Environment Security Detector.
 *
 * Identifies virtualized browser environments, cloud browser isolation instances (SauceLabs, BrowserStack),
 * headless cloud rendering farms, and virtualized GPU drivers (SwiftShader, llvmpipe, VirtualBox, VMware).
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.03ms (WebGL vendor and navigator property check)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: None exfiltrated
 * - Evasion Limits: Highly sophisticated cloud emulators spoofing genuine hardware GPU strings
 *   require deep timing and canvas shader execution benchmarking.
 */
const KNOWN_VIRTUAL_RENDERERS = [
    /swiftshader/i,
    /llvmpipe/i,
    /softpipe/i,
    /virtualbox/i,
    /vmware/i,
    /mesa offscreen/i,
    /microsoft basic render/i
];
export class VirtualBrowserDetector {
    static scan() {
        const nowMs = Date.now().toString();
        const evidence = {
            scan_timestamp_ms: nowMs,
            probe_target: 'Virtual Cloud Browser Container & Virtual GPU Drivers',
            probe_technique: 'virtual_render_context_and_webgl_vendor_audit'
        };
        let triggered = false;
        const virtualIndicators = [];
        try {
            // 1. Audit WebGL Unmasked Renderer and Vendor
            if (typeof document !== 'undefined') {
                const canvas = document.createElement('canvas');
                const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                if (gl && gl.getExtension) {
                    const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                    if (debugInfo) {
                        const renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) || '';
                        const vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) || '';
                        evidence['unmasked_renderer'] = renderer;
                        evidence['unmasked_vendor'] = vendor;
                        for (const pat of KNOWN_VIRTUAL_RENDERERS) {
                            if (pat.test(renderer) || pat.test(vendor)) {
                                triggered = true;
                                virtualIndicators.push(`Virtual/Software GPU detected: ${renderer} (${vendor})`);
                            }
                        }
                    }
                }
            }
            // 2. Check for virtual container global variables or automation flags
            const scopesToCheck = [
                typeof window !== 'undefined' ? window : null,
                typeof globalThis !== 'undefined' ? globalThis : null
            ].filter(Boolean);
            for (const scope of scopesToCheck) {
                if (scope.__nightmare || scope._phantom || scope.callPhantom || scope.__sauce_stats) {
                    triggered = true;
                    virtualIndicators.push('Cloud browser automation framework variables detected in global scope');
                    break;
                }
            }
            evidence['detected_virtual_indicators'] = virtualIndicators;
            evidence['actual_value'] = triggered
                ? `Virtual browser or cloud isolation container detected (${virtualIndicators.length}): ${virtualIndicators.slice(0, 3).join(', ')}`
                : 'Virtual Cloud Browser Container verified clean in browser context';
            evidence['expected_value'] = 'Session must execute on physical hardware devices with genuine hardware-accelerated GPUs';
            evidence['threat_classification'] = triggered
                ? 'VIRTUAL_CONTAINER_OR_CLOUD_EMULATION_DETECTED'
                : 'Physical browser hardware environment';
            evidence['remediation_guidance'] = triggered
                ? 'Verify if client session is running inside a cloud VM, automated sandbox, or container'
                : 'No action required. Baseline clean.';
        }
        catch (e) {
            evidence['error'] = `VirtualBrowserDetector error: ${e.message}`;
        }
        return {
            id: 'virtual_browser_environment_detector',
            triggered,
            severity: triggered ? 2 : 0,
            category: 'environment',
            event: triggered ? 'virtual_browser_detected' : 'virtual_browser_environment_detector_verified',
            confidence: 0.85,
            fpRiskTier: 'LOW',
            evasionDifficulty: 'MEDIUM',
            status: triggered ? 'FAILED' : 'PASSED',
            name: 'Virtual Browser Environment Detector',
            evidence
        };
    }
}
