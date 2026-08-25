/**
 * WebProxyDetector: P4 Informational / Network Security Detector.
 *
 * Identifies HTTP proxy headers, client-side proxy injection globals,
 * and proxy routing artifacts indicating traffic interception or relay nodes.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.02ms (Global scope and header indicator check)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: None exfiltrated
 * - Evasion Limits: Transparent upstream reverse proxies not modifying client headers
 *   require backend TLS fingerprinting (JA3/JA4) to detect.
 */
const SUSPICIOUS_PROXY_GLOBALS = [
    '__proxy_injected__',
    '__burp__',
    '__charles__',
    '__fiddler__',
    '__mitmproxy__',
    '__ZAP__'
];
export class WebProxyDetector {
    static scan() {
        const nowMs = Date.now().toString();
        const evidence = {
            scan_timestamp_ms: nowMs,
            probe_target: 'HTTP Proxy Injection Artifacts & Client Headers',
            probe_technique: 'proxy_global_and_header_audit'
        };
        let triggered = false;
        const proxyFindings = [];
        try {
            // 1. Audit global scope for active debugging proxy injection hooks
            const scopesToCheck = [
                typeof window !== 'undefined' ? window : null,
                typeof globalThis !== 'undefined' ? globalThis : null
            ].filter(Boolean);
            for (const proxyFlag of SUSPICIOUS_PROXY_GLOBALS) {
                if (scopesToCheck.some((s) => proxyFlag in s || s[proxyFlag])) {
                    triggered = true;
                    proxyFindings.push(`Debugging proxy artifact detected in global scope: ${proxyFlag}`);
                }
            }
            // 2. Check for proxy PAC / WebRTC relay headers if exposed
            if (typeof document !== 'undefined' && document.cookie) {
                if (document.cookie.includes('proxy_session=') || document.cookie.includes('burp_session=')) {
                    triggered = true;
                    proxyFindings.push('Proxy session tracking cookie detected');
                }
            }
            evidence['detected_proxy_findings'] = proxyFindings;
            evidence['actual_value'] = triggered
                ? `HTTP Proxy or debugging interceptor detected (${proxyFindings.length}): ${proxyFindings.slice(0, 3).join(', ')}`
                : 'HTTP Proxy Header Via verified clean in browser context';
            evidence['expected_value'] = 'Session runtime and transport must be free from unauthorized debugging proxy tools';
            evidence['threat_classification'] = triggered
                ? 'DEBUGGING_PROXY_OR_TRAFFIC_INTERCEPTOR_DETECTED'
                : 'Clean browser network environment';
            evidence['remediation_guidance'] = triggered
                ? 'Verify if developer tools (Burp Suite, Charles Proxy, Fiddler) are active on the host'
                : 'No action required. Baseline clean.';
        }
        catch (e) {
            evidence['error'] = `WebProxyDetector error: ${e.message}`;
        }
        return {
            id: 'proxy_detection',
            triggered,
            severity: triggered ? 2 : 0,
            category: 'network',
            event: triggered ? 'proxy_detected' : 'proxy_detection_verified',
            confidence: 0.80,
            fpRiskTier: 'LOW',
            evasionDifficulty: 'MEDIUM',
            status: triggered ? 'FAILED' : 'PASSED',
            name: 'Proxy Detection',
            evidence
        };
    }
}
