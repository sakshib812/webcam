/**
 * HttpsEnforcementDetector: P4 Informational / Network Security Detector.
 *
 * Verifies that the web application is running over encrypted transport (HTTPS)
 * and flags unencrypted HTTP sessions that expose user credentials to MITM interception.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.01ms (Simple protocol and hostname check)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: None exfiltrated
 * - Evasion Limits: Local loopback hosts (localhost, 127.0.0.1) are granted development exemptions.
 */
export class HttpsEnforcementDetector {
    static scan() {
        const nowMs = Date.now().toString();
        const evidence = {
            scan_timestamp_ms: nowMs,
            probe_target: 'HTTPS Transport Protocol Scheme Enforcement',
            probe_technique: 'location_protocol_scheme_audit'
        };
        let triggered = false;
        const protocolFindings = [];
        try {
            if (typeof window !== 'undefined' && window.location) {
                const protocol = window.location.protocol || '';
                const hostname = window.location.hostname || '';
                evidence['current_protocol'] = protocol;
                evidence['current_hostname'] = hostname;
                const isLocalhost = hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]' || hostname.endsWith('.local');
                if (protocol === 'http:' && !isLocalhost) {
                    triggered = true;
                    protocolFindings.push(`Insecure HTTP transport active on production host: ${hostname}`);
                }
            }
            evidence['detected_protocol_findings'] = protocolFindings;
            evidence['actual_value'] = triggered
                ? `Insecure transport detected (${protocolFindings.length}): ${protocolFindings.join('; ')}`
                : 'HTTPS Protocol Scheme Enforcement verified clean in browser context';
            evidence['expected_value'] = 'Application must be served exclusively over encrypted HTTPS transport';
            evidence['threat_classification'] = triggered
                ? 'UNENCRYPTED_HTTP_TRANSPORT_ACTIVE'
                : 'Clean browser environment';
            evidence['remediation_guidance'] = triggered
                ? 'Enforce HTTP Strict Transport Security (HSTS) and configure server-side 301 redirect to HTTPS'
                : 'No action required. Baseline clean.';
        }
        catch (e) {
            evidence['error'] = `HttpsEnforcementDetector error: ${e.message}`;
        }
        return {
            id: 'https_enforcement_detector',
            triggered,
            severity: triggered ? 4 : 0,
            category: 'network',
            event: triggered ? 'https_enforcement_violation' : 'https_enforcement_detector_verified',
            confidence: 0.95,
            fpRiskTier: 'LOW',
            evasionDifficulty: 'LOW',
            status: triggered ? 'FAILED' : 'PASSED',
            name: 'HTTPS Enforcement Detector',
            evidence
        };
    }
}
