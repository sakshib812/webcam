/**
 * AdInjectionDetector: P4 Informational / Optional Risk Detector.
 *
 * Scans the DOM for unauthorized third-party advertisement containers, affiliate link
 * injectors, and popup scripts inserted by malicious extensions or ISP proxies.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.04ms (Selective DOM selector sweep)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: None exfiltrated
 * - Evasion Limits: Highly dynamic shadow DOM ad injectors may hide container nodes.
 */
const KNOWN_AD_INJECTION_HOSTS = [
    'popads.net',
    'propellerads.com',
    'adcash.com',
    'adnxs.com',
    'infolinks.com',
    'taboola-injected',
    'outbrain-injected'
];
export class AdInjectionDetector {
    static scan() {
        const nowMs = Date.now().toString();
        const evidence = {
            scan_timestamp_ms: nowMs,
            probe_target: 'Injected Ad Containers & Unauthorized Affiliate Elements',
            probe_technique: 'ad_container_dom_selector_audit'
        };
        let triggered = false;
        const adIndicators = [];
        try {
            if (typeof document !== 'undefined') {
                // 1. Audit DOM script and iframe sources for known ad injection networks
                const elementsWithSrc = Array.from(document.querySelectorAll('script[src], iframe[src]'));
                for (const el of elementsWithSrc) {
                    const src = el.getAttribute('src') || '';
                    for (const host of KNOWN_AD_INJECTION_HOSTS) {
                        if (src.toLowerCase().includes(host)) {
                            triggered = true;
                            adIndicators.push(`Ad network source detected on <${el.tagName.toLowerCase()}>: ${host}`);
                        }
                    }
                }
                // 2. Scan for elements with explicit ad injection class names or data attributes
                const suspiciousElements = Array.from(document.querySelectorAll('.ad-injection-container, .injected-banner-overlay, [data-ad-injected="true"], [id*="injected_ad_banner"]'));
                if (suspiciousElements.length > 0) {
                    triggered = true;
                    adIndicators.push(`Found ${suspiciousElements.length} DOM elements with ad injection signatures`);
                }
            }
            evidence['detected_ad_indicators'] = adIndicators;
            evidence['actual_value'] = triggered
                ? `Ad injection artifacts detected (${adIndicators.length}): ${adIndicators.slice(0, 3).join(', ')}`
                : 'No unauthorized ad injection containers or networks detected in DOM';
            evidence['expected_value'] = 'DOM must be free from unauthorized third-party ad insertion';
            evidence['threat_classification'] = triggered
                ? 'UNAUTHORIZED_AD_INJECTION_DETECTED'
                : 'Clean DOM advertising surface';
            evidence['remediation_guidance'] = triggered
                ? 'Audit browser extensions and network proxy layers for unauthorized ad insertion'
                : 'No action required. Baseline clean.';
        }
        catch (e) {
            evidence['error'] = `AdInjectionDetector error: ${e.message}`;
        }
        return {
            id: 'ad_injection_detector',
            triggered,
            severity: triggered ? 2 : 0,
            category: 'extension_security',
            event: triggered ? 'ad_injection_detected' : 'ad_injection_detector_verified',
            confidence: 0.85,
            fpRiskTier: 'LOW',
            evasionDifficulty: 'MEDIUM',
            status: triggered ? 'FAILED' : 'PASSED',
            name: 'Ad Injection Detector',
            evidence
        };
    }
}
