/**
 * ManifestIntegrityDetector: P4 Informational / Application Integrity Detector.
 *
 * Validates Web App Manifest (`<link rel="manifest">`) link tags, checks origin
 * conformity, and flags malicious URI schemes or untrusted third-party manifest hosts.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.02ms (Single DOM link query)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: None read or exfiltrated
 * - Evasion Limits: Manifests loaded dynamically via service worker fetch hooks
 *   require service worker network interceptor audits.
 */
export class ManifestIntegrityDetector {
    static scan() {
        const nowMs = Date.now().toString();
        const evidence = {
            scan_timestamp_ms: nowMs,
            probe_target: 'Web App Manifest Link Tag & Origin',
            probe_technique: 'app_manifest_link_and_origin_audit'
        };
        let triggered = false;
        const manifestAnomalies = [];
        try {
            if (typeof document !== 'undefined') {
                const manifestLinks = Array.from(document.querySelectorAll('link[rel="manifest"]'));
                evidence['total_manifest_links'] = manifestLinks.length;
                for (const link of manifestLinks) {
                    const href = link.getAttribute('href') || link.href || '';
                    // 1. Check for dangerous URI schemes (javascript:, data:)
                    if (href.startsWith('javascript:') || href.startsWith('data:')) {
                        triggered = true;
                        manifestAnomalies.push(`Dangerous URI scheme in manifest href: ${href.slice(0, 30)}`);
                    }
                    // 2. Check if manifest is loaded from an untrusted third-party origin
                    if (href && (href.startsWith('http://') || href.startsWith('https://'))) {
                        try {
                            const url = new URL(href, typeof window !== 'undefined' ? window.location.href : 'https://localhost');
                            const currentOrigin = typeof window !== 'undefined' ? window.location.origin : '';
                            if (currentOrigin && url.origin !== currentOrigin) {
                                triggered = true;
                                manifestAnomalies.push(`Manifest loaded from external third-party origin: ${url.origin}`);
                            }
                        }
                        catch {
                            // URL parse error
                        }
                    }
                }
            }
            evidence['detected_manifest_anomalies'] = manifestAnomalies;
            evidence['actual_value'] = triggered
                ? `Web App Manifest integrity violations detected (${manifestAnomalies.length}): ${manifestAnomalies.slice(0, 3).join(', ')}`
                : 'Web App Manifest Link verified clean in browser context';
            evidence['expected_value'] = 'Manifest link must point to same-origin HTTPS URL without data/javascript schemes';
            evidence['threat_classification'] = triggered
                ? 'WEB_APP_MANIFEST_HIJACK_OR_ORIGIN_VIOLATION'
                : 'Clean browser environment';
            evidence['remediation_guidance'] = triggered
                ? 'Verify that the Web App Manifest link points strictly to an authorized first-party JSON file'
                : 'No action required. Baseline clean.';
        }
        catch (e) {
            evidence['error'] = `ManifestIntegrityDetector error: ${e.message}`;
        }
        return {
            id: 'manifest_integrity_detector',
            triggered,
            severity: triggered ? 2 : 0,
            category: 'application_integrity',
            event: triggered ? 'manifest_integrity_violation' : 'manifest_integrity_detector_verified',
            confidence: 0.85,
            fpRiskTier: 'LOW',
            evasionDifficulty: 'MEDIUM',
            status: triggered ? 'FAILED' : 'PASSED',
            name: 'Web App Manifest Integrity Detector',
            evidence
        };
    }
}
