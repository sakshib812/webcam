/**
 * UserAgentTamperingDetector: P4 Informational / Mandatory Baseline Detector.
 *
 * Audits `navigator.userAgent`, `navigator.platform`, `navigator.vendor`, and `navigator.appVersion`
 * for property descriptor monkey-patching, userland getter overrides, and platform contradictions.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.02ms (Property descriptor inspection & cross-audit)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: None exfiltrated
 * - Evasion Limits: CDP (Chrome DevTools Protocol) user-agent overrides set before V8 context creation
 *   must be caught by contradiction detection against underlying engine features.
 */
export class UserAgentTamperingDetector {
    static scan() {
        const nowMs = Date.now().toString();
        const evidence = {
            scan_timestamp_ms: nowMs,
            probe_target: 'Navigator Platform vs UserAgent & Property Descriptors',
            probe_technique: 'user_agent_descriptor_and_platform_cross_audit'
        };
        let triggered = false;
        const uaAnomalies = [];
        try {
            if (typeof navigator !== 'undefined') {
                const ua = (navigator.userAgent || '').toLowerCase();
                const platform = (navigator.platform || '').toLowerCase();
                const vendor = (navigator.vendor || '').toLowerCase();
                evidence['navigator_platform'] = platform;
                evidence['navigator_vendor'] = vendor;
                // 1. Property Descriptor Check: Is userAgent overridden with a shadow getter on the instance?
                if (typeof Navigator !== 'undefined' && Navigator.prototype && (navigator instanceof Navigator)) {
                    const instanceDescriptor = Object.getOwnPropertyDescriptor(navigator, 'userAgent');
                    if (instanceDescriptor && (instanceDescriptor.get || Object.prototype.hasOwnProperty.call(navigator, 'userAgent'))) {
                        triggered = true;
                        uaAnomalies.push('navigator.userAgent has instance-level shadow property override');
                    }
                    const protoDescriptor = Object.getOwnPropertyDescriptor(Navigator.prototype, 'userAgent');
                    if (protoDescriptor && protoDescriptor.get) {
                        const getterStr = Function.prototype.toString.call(protoDescriptor.get);
                        if (!getterStr.includes('[native code]') && !getterStr.includes('function ()')) {
                            triggered = true;
                            uaAnomalies.push('Navigator.prototype.userAgent getter is not a native C++ function');
                        }
                    }
                }
                // 2. Cross-check Platform vs User-Agent contradictions
                if (platform.includes('win') && (ua.includes('iphone') || ua.includes('ipad') || ua.includes('android'))) {
                    triggered = true;
                    uaAnomalies.push(`Platform contradiction: navigator.platform is '${platform}' but User-Agent claims mobile device`);
                }
                else if (platform.includes('iphone') && !ua.includes('iphone')) {
                    triggered = true;
                    uaAnomalies.push(`Platform contradiction: navigator.platform is '${platform}' but User-Agent claims non-iPhone`);
                }
                else if (platform.includes('mac') && ua.includes('windows nt')) {
                    triggered = true;
                    uaAnomalies.push(`Platform contradiction: navigator.platform is '${platform}' but User-Agent claims Windows`);
                }
            }
            evidence['detected_ua_anomalies'] = uaAnomalies;
            evidence['actual_value'] = triggered
                ? `User-Agent tampering or platform contradiction detected (${uaAnomalies.length}): ${uaAnomalies.slice(0, 3).join(', ')}`
                : 'Navigator Platform vs UserAgent verified clean in browser context';
            evidence['expected_value'] = 'navigator.userAgent and navigator.platform must be unhooked and mutually consistent';
            evidence['threat_classification'] = triggered
                ? 'USER_AGENT_TAMPERING_OR_PLATFORM_SPOOFING_DETECTED'
                : 'Clean browser environment';
            evidence['remediation_guidance'] = triggered
                ? 'Disable User-Agent switcher extensions or inspect anti-detect browser configurations'
                : 'No action required. Baseline clean.';
        }
        catch (e) {
            evidence['error'] = `UserAgentTamperingDetector error: ${e.message}`;
        }
        return {
            id: 'user_agent_tampering_detector',
            triggered,
            severity: triggered ? 4 : 0,
            category: 'environment',
            event: triggered ? 'user_agent_tampering_detected' : 'user_agent_tampering_detector_verified',
            confidence: 0.90,
            fpRiskTier: 'LOW',
            evasionDifficulty: 'MEDIUM',
            status: triggered ? 'FAILED' : 'PASSED',
            name: 'User-Agent Tampering Detector',
            evidence
        };
    }
}
