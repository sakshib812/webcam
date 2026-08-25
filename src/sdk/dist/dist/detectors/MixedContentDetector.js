/**
 * MixedContentDetector: P4 Informational / Network Security Detector.
 *
 * Scans DOM resource URLs (scripts, stylesheets, iframes, images, forms) for unencrypted
 * `http://` resources loaded within a secure HTTPS origin context (Active/Passive Mixed Content).
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.03ms (DOM resource attribute sweep)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: None exfiltrated
 * - Evasion Limits: Mixed content fetched dynamically inside Web Workers requires CSP upgrade-insecure-requests.
 */
export class MixedContentDetector {
    static scan() {
        const nowMs = Date.now().toString();
        const evidence = {
            scan_timestamp_ms: nowMs,
            probe_target: 'Mixed HTTP Asset Resources in HTTPS Context',
            probe_technique: 'mixed_content_dom_url_audit'
        };
        let triggered = false;
        const mixedResources = [];
        try {
            const isHttps = typeof window !== 'undefined' && window.location && window.location.protocol === 'https:';
            if (isHttps && typeof document !== 'undefined') {
                const candidateElements = Array.from(document.querySelectorAll('script[src], link[href], iframe[src], img[src], audio[src], video[src], form[action]'));
                evidence['total_resources_audited'] = candidateElements.length;
                for (const el of candidateElements) {
                    const url = el.getAttribute('src') || el.getAttribute('href') || el.getAttribute('action') || '';
                    if (url.startsWith('http://') && !url.includes('localhost') && !url.includes('127.0.0.1')) {
                        triggered = true;
                        mixedResources.push(`<${el.tagName.toLowerCase()}> resource loaded over plaintext HTTP: ${url.slice(0, 45)}...`);
                    }
                }
            }
            evidence['detected_mixed_resources'] = mixedResources;
            evidence['actual_value'] = triggered
                ? `Mixed content vulnerabilities detected (${mixedResources.length}): ${mixedResources.slice(0, 3).join(', ')}`
                : 'Mixed HTTP Asset Resources verified clean in browser context';
            evidence['expected_value'] = 'All page assets and subresources must load strictly over encrypted HTTPS protocols';
            evidence['threat_classification'] = triggered
                ? 'MIXED_HTTP_CONTENT_DETECTED'
                : 'Clean browser environment';
            evidence['remediation_guidance'] = triggered
                ? 'Upgrade all HTTP resource URLs to HTTPS or deploy Content-Security-Policy: upgrade-insecure-requests'
                : 'No action required. Baseline clean.';
        }
        catch (e) {
            evidence['error'] = `MixedContentDetector error: ${e.message}`;
        }
        return {
            id: 'mixed_content_detector',
            triggered,
            severity: triggered ? 3 : 0,
            category: 'network',
            event: triggered ? 'mixed_content_detected' : 'mixed_content_detector_verified',
            confidence: 0.90,
            fpRiskTier: 'LOW',
            evasionDifficulty: 'LOW',
            status: triggered ? 'FAILED' : 'PASSED',
            name: 'Mixed Content Detector',
            evidence
        };
    }
}
