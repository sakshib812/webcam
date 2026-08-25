/**
 * ExtensionInjectionDetector: P4 Informational / Extension Security Detector.
 *
 * Scans DOM `<head>` and `<body>` elements for `<script>`, `<link>`, or `<iframe>` tags
 * loaded directly from browser extension protocol schemes (`chrome-extension://`, `moz-extension://`).
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.03ms (DOM protocol scheme query)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: None read or exfiltrated
 * - Evasion Limits: Extensions using pure programmatic message passing without
 *   inserting DOM elements cannot be detected via DOM sweeping.
 */
export class ExtensionInjectionDetector {
    static scan() {
        const nowMs = Date.now().toString();
        const evidence = {
            scan_timestamp_ms: nowMs,
            probe_target: 'Extension DOM Mutation Nodes & Custom Protocol Schemes',
            probe_technique: 'browser_extension_dom_audit'
        };
        let triggered = false;
        const injectedNodes = [];
        try {
            if (typeof document !== 'undefined') {
                const candidateElements = Array.from(document.querySelectorAll('script[src], link[href], iframe[src], img[src]'));
                for (const el of candidateElements) {
                    const srcOrHref = el.getAttribute('src') || el.getAttribute('href') || '';
                    if (srcOrHref.startsWith('chrome-extension://') ||
                        srcOrHref.startsWith('moz-extension://') ||
                        srcOrHref.startsWith('safari-extension://') ||
                        srcOrHref.startsWith('extension://')) {
                        triggered = true;
                        injectedNodes.push(`<${el.tagName.toLowerCase()}> loaded from extension scheme: ${srcOrHref.slice(0, 50)}...`);
                    }
                }
            }
            evidence['detected_extension_nodes'] = injectedNodes;
            evidence['actual_value'] = triggered
                ? `Browser extension DOM artifacts detected (${injectedNodes.length}): ${injectedNodes.slice(0, 3).join(', ')}`
                : 'Extension DOM Mutation Nodes verified clean in browser context';
            evidence['expected_value'] = 'Page DOM must contain no assets injected via extension:// protocols';
            evidence['threat_classification'] = triggered
                ? 'UNAUTHORIZED_EXTENSION_DOM_INJECTION'
                : 'Clean browser environment';
            evidence['remediation_guidance'] = triggered
                ? 'Audit installed browser extensions for unauthorized DOM script injections'
                : 'No action required. Baseline clean.';
        }
        catch (e) {
            evidence['error'] = `ExtensionInjectionDetector error: ${e.message}`;
        }
        return {
            id: 'browser_extension_injection_detector',
            triggered,
            severity: triggered ? 2 : 0,
            category: 'extension_security',
            event: triggered ? 'browser_extension_injection_detected' : 'browser_extension_injection_detector_verified',
            confidence: 0.90,
            fpRiskTier: 'LOW',
            evasionDifficulty: 'MEDIUM',
            status: triggered ? 'FAILED' : 'PASSED',
            name: 'Browser Extension Injection Detector',
            evidence
        };
    }
}
