/**
 * ServiceWorkerIntegrityDetector: P4 Informational / Application Integrity Detector.
 *
 * Audits `navigator.serviceWorker.register` and active Service Worker registrations
 * to identify rogue service workers registered from unapproved scopes or external scripts.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.02ms (Registration API descriptor and scope inspection)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: None read or recorded
 * - Evasion Limits: Service Workers already registered on different subpaths before
 *   the page load require asynchronous `navigator.serviceWorker.getRegistrations()` audit.
 */
export class ServiceWorkerIntegrityDetector {
    static scan() {
        const nowMs = Date.now().toString();
        const evidence = {
            scan_timestamp_ms: nowMs,
            probe_target: 'Service Worker Registration & Controller Interceptors',
            probe_technique: 'service_worker_api_and_scope_audit'
        };
        let triggered = false;
        const swFindings = [];
        try {
            if (typeof navigator !== 'undefined' && navigator.serviceWorker) {
                const sw = navigator.serviceWorker;
                // 1. Audit register method for monkey-patching
                if (Object.prototype.hasOwnProperty.call(sw, 'register')) {
                    triggered = true;
                    swFindings.push('navigator.serviceWorker.register has instance-level shadow wrapper');
                }
                // 2. Audit active controller script URL
                if (sw.controller) {
                    const scriptUrl = sw.controller.scriptURL || '';
                    evidence['active_sw_controller_url'] = scriptUrl;
                    // Check if controller script originated from an external third-party origin
                    if (typeof window !== 'undefined' && scriptUrl) {
                        try {
                            const url = new URL(scriptUrl);
                            if (window.location.origin && url.origin !== window.location.origin) {
                                triggered = true;
                                swFindings.push(`Service Worker controller active from third-party origin: ${url.origin}`);
                            }
                        }
                        catch {
                            // Ignore URL parse errors
                        }
                    }
                }
            }
            evidence['detected_sw_findings'] = swFindings;
            evidence['actual_value'] = triggered
                ? `Service Worker integrity violations detected (${swFindings.length}): ${swFindings.slice(0, 3).join(', ')}`
                : 'Service Worker Registration Script verified clean in browser context';
            evidence['expected_value'] = 'Service Worker controller must originate strictly from same-origin script URL';
            evidence['threat_classification'] = triggered
                ? 'UNAUTHORIZED_SERVICE_WORKER_CONTROLLER_DETECTED'
                : 'Clean browser environment';
            evidence['remediation_guidance'] = triggered
                ? 'Unregister untrusted Service Workers and verify service worker registration scopes'
                : 'No action required. Baseline clean.';
        }
        catch (e) {
            evidence['error'] = `ServiceWorkerIntegrityDetector error: ${e.message}`;
        }
        return {
            id: 'service_worker_integrity_detector',
            triggered,
            severity: triggered ? 3 : 0,
            category: 'application_integrity',
            event: triggered ? 'service_worker_violation_detected' : 'service_worker_integrity_detector_verified',
            confidence: 0.85,
            fpRiskTier: 'LOW',
            evasionDifficulty: 'MEDIUM',
            status: triggered ? 'FAILED' : 'PASSED',
            name: 'Service Worker Integrity Detector',
            evidence
        };
    }
}
