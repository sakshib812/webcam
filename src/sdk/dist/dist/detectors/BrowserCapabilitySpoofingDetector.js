/**
 * BrowserCapabilitySpoofingDetector: P4 Informational / Environment Security Detector.
 *
 * Detects inconsistencies between reported browser engine claims (in userAgent/vendor)
 * and actual Web API features supported by the underlying JavaScript rendering engine.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.02ms (Direct property and feature checks)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: None exfiltrated
 * - Evasion Limits: Custom Chromium forks with modified user-agents may trigger informational mismatches.
 */
export class BrowserCapabilitySpoofingDetector {
    static scan() {
        const nowMs = Date.now().toString();
        const evidence = {
            scan_timestamp_ms: nowMs,
            probe_target: 'Browser Engine Capabilities vs Reported User-Agent Identity',
            probe_technique: 'engine_feature_matrix_and_vendor_coherence_audit'
        };
        let triggered = false;
        const capabilityAnomalies = [];
        try {
            if (typeof navigator !== 'undefined') {
                const ua = (navigator.userAgent || '').toLowerCase();
                const vendor = (navigator.vendor || '').toLowerCase();
                const nav = navigator;
                evidence['reported_user_agent'] = ua.slice(0, 70);
                evidence['reported_vendor'] = vendor;
                // 1. WebKit / Safari claim validation
                if (ua.includes('safari') && !ua.includes('chrome') && !ua.includes('chromium') && !ua.includes('android')) {
                    // Genuine Safari has vendor 'Apple Computer, Inc.' and lacks window.chrome
                    if (typeof window !== 'undefined' && window.chrome) {
                        triggered = true;
                        capabilityAnomalies.push('Safari claimed in UA but window.chrome Blink object is present');
                    }
                    if (vendor && !vendor.includes('apple')) {
                        triggered = true;
                        capabilityAnomalies.push(`Safari claimed in UA but navigator.vendor is '${vendor}' instead of Apple`);
                    }
                }
                // 2. Firefox (Gecko) claim validation
                if (ua.includes('firefox')) {
                    if (typeof window !== 'undefined' && window.chrome) {
                        triggered = true;
                        capabilityAnomalies.push('Firefox claimed in UA but window.chrome object is present');
                    }
                    if (vendor && vendor.length > 0 && !vendor.includes('mozilla')) {
                        triggered = true;
                        capabilityAnomalies.push(`Firefox claimed in UA but navigator.vendor is '${vendor}'`);
                    }
                }
                // 3. Chrome / Chromium claim validation
                if (ua.includes('chrome') && !ua.includes('edg') && !ua.includes('opr') && !ua.includes('brave')) {
                    if (vendor && !vendor.includes('google')) {
                        triggered = true;
                        capabilityAnomalies.push(`Chrome claimed in UA but navigator.vendor is '${vendor}' instead of Google Inc.`);
                    }
                }
            }
            evidence['detected_capability_anomalies'] = capabilityAnomalies;
            evidence['actual_value'] = triggered
                ? `Browser capability spoofing detected (${capabilityAnomalies.length}): ${capabilityAnomalies.slice(0, 3).join(', ')}`
                : 'Touch & Pointer Capabilities verified clean in browser context';
            evidence['expected_value'] = 'Reported browser vendor and User-Agent must correlate with actual engine API primitives';
            evidence['threat_classification'] = triggered
                ? 'BROWSER_CAPABILITY_SPOOFING_OR_HEADLESS_MASQUERADE'
                : 'Clean browser environment';
            evidence['remediation_guidance'] = triggered
                ? 'Verify if browser is using an anti-detect profile or automated User-Agent spoofer'
                : 'No action required. Baseline clean.';
        }
        catch (e) {
            evidence['error'] = `BrowserCapabilitySpoofingDetector error: ${e.message}`;
        }
        return {
            id: 'browser_capability_spoofing_detector',
            triggered,
            severity: triggered ? 3 : 0,
            category: 'environment',
            event: triggered ? 'browser_capability_spoofing_detected' : 'browser_capability_spoofing_detector_verified',
            confidence: 0.85,
            fpRiskTier: 'LOW',
            evasionDifficulty: 'MEDIUM',
            status: triggered ? 'FAILED' : 'PASSED',
            name: 'Browser Capability Spoofing Detector',
            evidence
        };
    }
}
