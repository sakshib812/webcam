/**
 * BrowserVersionIntegrityDetector: P4 Informational / Environment Security Detector.
 *
 * Cross-checks `navigator.userAgentData` (Client Hints) brands and versions against
 * `navigator.userAgent` and engine features to identify contradictory version spoofing.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.02ms (String extraction and regex comparison)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: None exfiltrated
 * - Evasion Limits: If Client Hints API is entirely absent (e.g. Firefox/Safari), version audit relies on UA pattern parsing.
 */
export class BrowserVersionIntegrityDetector {
    static scan() {
        const nowMs = Date.now().toString();
        const evidence = {
            scan_timestamp_ms: nowMs,
            probe_target: 'UserAgentData Client Hints vs UserAgent Major Version',
            probe_technique: 'client_hints_and_ua_version_cross_audit'
        };
        let triggered = false;
        const versionAnomalies = [];
        try {
            if (typeof navigator !== 'undefined') {
                const ua = navigator.userAgent || '';
                const nav = navigator;
                // 1. Extract major version from User-Agent string
                let uaMajorVersion = null;
                const chromeMatch = ua.match(/Chrome\/(\d+)\./i);
                const firefoxMatch = ua.match(/Firefox\/(\d+)\./i);
                const safariMatch = ua.match(/Version\/(\d+)\./i);
                if (chromeMatch)
                    uaMajorVersion = parseInt(chromeMatch[1], 10);
                else if (firefoxMatch)
                    uaMajorVersion = parseInt(firefoxMatch[1], 10);
                else if (safariMatch)
                    uaMajorVersion = parseInt(safariMatch[1], 10);
                evidence['extracted_ua_major_version'] = uaMajorVersion;
                // 2. Cross-check against navigator.userAgentData (Client Hints)
                if (nav.userAgentData && nav.userAgentData.brands) {
                    const brands = nav.userAgentData.brands;
                    evidence['client_hints_brands'] = JSON.stringify(brands);
                    // Find primary brand matching Chrome/Chromium
                    const primaryBrand = brands.find((b) => /Chromium|Google Chrome|Microsoft Edge/i.test(b.brand));
                    if (primaryBrand && uaMajorVersion !== null) {
                        const chMajorVersion = parseInt(primaryBrand.version, 10);
                        if (!isNaN(chMajorVersion) && Math.abs(chMajorVersion - uaMajorVersion) > 2) {
                            triggered = true;
                            versionAnomalies.push(`Version contradiction: User-Agent reports v${uaMajorVersion} but Client Hints brand '${primaryBrand.brand}' reports v${chMajorVersion}`);
                        }
                    }
                    // Check platform coherence
                    if (nav.userAgentData.platform) {
                        const chPlatform = nav.userAgentData.platform.toLowerCase();
                        const uaLower = ua.toLowerCase();
                        if (chPlatform.includes('win') && (uaLower.includes('macintosh') || uaLower.includes('android') || uaLower.includes('iphone'))) {
                            triggered = true;
                            versionAnomalies.push(`Platform contradiction: Client Hints says '${chPlatform}' but User-Agent says non-Windows`);
                        }
                        else if (chPlatform.includes('mac') && (uaLower.includes('windows') || uaLower.includes('android'))) {
                            triggered = true;
                            versionAnomalies.push(`Platform contradiction: Client Hints says '${chPlatform}' but User-Agent says non-macOS`);
                        }
                    }
                }
            }
            evidence['detected_version_anomalies'] = versionAnomalies;
            evidence['actual_value'] = triggered
                ? `Browser version or platform contradiction detected (${versionAnomalies.length}): ${versionAnomalies.slice(0, 3).join(', ')}`
                : 'UserAgentData Client Hints verified clean in browser context';
            evidence['expected_value'] = 'UserAgentData Client Hints and navigator.userAgent must report coherent versions and platforms';
            evidence['threat_classification'] = triggered
                ? 'BROWSER_VERSION_OR_PLATFORM_SPOOFING_DETECTED'
                : 'Clean browser environment';
            evidence['remediation_guidance'] = triggered
                ? 'Inspect user agent switcher extensions or automated crawler emulation headers'
                : 'No action required. Baseline clean.';
        }
        catch (e) {
            evidence['error'] = `BrowserVersionIntegrityDetector error: ${e.message}`;
        }
        return {
            id: 'browser_version_integrity_detector',
            triggered,
            severity: triggered ? 3 : 0,
            category: 'environment',
            event: triggered ? 'browser_version_anomaly_detected' : 'browser_version_integrity_detector_verified',
            confidence: 0.85,
            fpRiskTier: 'LOW',
            evasionDifficulty: 'MEDIUM',
            status: triggered ? 'FAILED' : 'PASSED',
            name: 'Browser Version Integrity Detector',
            evidence
        };
    }
}
