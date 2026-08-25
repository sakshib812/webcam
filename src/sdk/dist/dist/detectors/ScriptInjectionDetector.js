// Injected dynamic mutations tracked by MutationObserver
const OBSERVED_MUTATION_INJECTIONS = [];
let isObserverActive = false;
export class ScriptInjectionDetector {
    static defaultAllowedOrigins = [];
    /**
     * Configures global allowed script origins
     */
    static setAllowedOrigins(origins) {
        ScriptInjectionDetector.defaultAllowedOrigins = origins;
    }
    /**
     * Initializes a background MutationObserver on document to catch runtime script injections
     */
    static initObserver(options) {
        if (typeof window === 'undefined' || typeof document === 'undefined' || isObserverActive) {
            return;
        }
        try {
            const allowedOrigins = options?.allowedScriptOrigins || ScriptInjectionDetector.defaultAllowedOrigins;
            const targetNode = document.documentElement || document.body;
            if (!targetNode)
                return;
            const observer = new MutationObserver((mutations) => {
                for (const mutation of mutations) {
                    for (const node of Array.from(mutation.addedNodes)) {
                        if (node.nodeName === 'SCRIPT') {
                            const scriptEl = node;
                            const src = scriptEl.src || scriptEl.getAttribute('src') || '';
                            const content = scriptEl.textContent || scriptEl.innerHTML || '';
                            const isSuspicious = ScriptInjectionDetector.analyzeScript(src, content, allowedOrigins);
                            if (isSuspicious.flagged) {
                                OBSERVED_MUTATION_INJECTIONS.push({
                                    tag: 'SCRIPT',
                                    snippet: isSuspicious.reason,
                                    timestamp: Date.now()
                                });
                            }
                        }
                    }
                }
            });
            observer.observe(targetNode, {
                childList: true,
                subtree: true
            });
            isObserverActive = true;
        }
        catch {
            // MutationObserver initialization fail-safe
        }
    }
    /**
     * Analyzes an individual script source & content for suspicious patterns
     */
    static analyzeScript(src, content, allowedOrigins = []) {
        // 1. External Script Origin Allowlist Check
        if (src) {
            try {
                const scriptUrl = new URL(src, typeof window !== 'undefined' ? window.location.href : 'https://localhost');
                const currentOrigin = typeof window !== 'undefined' ? window.location.origin : '';
                const scriptOrigin = scriptUrl.origin;
                const isSameOrigin = currentOrigin && scriptOrigin === currentOrigin;
                const isAllowed = isSameOrigin || allowedOrigins.some((allowed) => {
                    if (allowed.startsWith('*.')) {
                        const domainSuffix = allowed.slice(2);
                        return scriptUrl.hostname.endsWith(domainSuffix);
                    }
                    return allowed === scriptOrigin || allowed === scriptUrl.hostname;
                });
                if (allowedOrigins.length > 0 && !isAllowed) {
                    return {
                        flagged: true,
                        reason: `External script loaded from unauthorized origin: ${scriptOrigin}`,
                        severity: 4
                    };
                }
            }
            catch {
                // Malformed URL in script src
                return {
                    flagged: true,
                    reason: `Malformed external script src attribute: ${src.slice(0, 50)}`,
                    severity: 3
                };
            }
        }
        // 2. Suspicious Inline Script Payloads (Base64 eval, string unescaping, obfuscated constructors)
        if (content) {
            const suspiciousPatterns = [
                { regex: /eval\s*\(\s*(atob|unescape|decodeURIComponent)\s*\(/i, name: 'Encoded eval execution (eval+atob/unescape)' },
                { regex: /Function\s*\(\s*(["'`])\s*eval\b/i, name: 'Dynamic Function constructor eval execution' },
                { regex: /\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}/i, name: 'Hex-encoded obfuscated string sequence' },
                { regex: /\\u[0-9a-f]{4}\\u[0-9a-f]{4}\\u[0-9a-f]{4}/i, name: 'Unicode-escaped obfuscated script payload' },
                { regex: /document\s*\.\s*write\s*\(\s*(unescape|atob)\s*\(/i, name: 'Encoded document.write injection' },
                { regex: /data:text\/javascript\s*;base64,/i, name: 'data: URI base64 executable script' }
            ];
            for (const pattern of suspiciousPatterns) {
                if (pattern.regex.test(content)) {
                    return {
                        flagged: true,
                        reason: `Suspicious payload signature detected: ${pattern.name}`,
                        severity: 5 // Critical P0 finding
                    };
                }
            }
        }
        return { flagged: false, reason: 'Clean', severity: 0 };
    }
    static scan(options) {
        const nowMs = Date.now().toString();
        const evidence = {
            scan_timestamp_ms: nowMs,
            probe_target: 'DOM Script Elements & Dynamic DOM Mutations',
            probe_technique: 'full_dom_script_sweep_and_mutation_pattern_audit'
        };
        let triggered = false;
        let maxSeverity = 0;
        const detectedInjections = [];
        const allowedOrigins = options?.allowedScriptOrigins || ScriptInjectionDetector.defaultAllowedOrigins;
        try {
            // 1. Audit accumulated dynamic MutationObserver injections
            if (OBSERVED_MUTATION_INJECTIONS.length > 0) {
                triggered = true;
                for (const inj of OBSERVED_MUTATION_INJECTIONS) {
                    detectedInjections.push(`[DYNAMIC_MUTATION] ${inj.snippet}`);
                }
                maxSeverity = Math.max(maxSeverity, 5);
            }
            // 2. Perform Full-DOM sweep of all current <script> elements
            if (typeof document !== 'undefined' && document.querySelectorAll) {
                const scripts = Array.from(document.querySelectorAll('script'));
                evidence['total_dom_scripts_audited'] = scripts.length;
                for (const script of scripts) {
                    const src = script.getAttribute('src') || script.src || '';
                    const content = script.textContent || script.innerHTML || '';
                    const analysis = ScriptInjectionDetector.analyzeScript(src, content, allowedOrigins);
                    if (analysis.flagged) {
                        triggered = true;
                        detectedInjections.push(analysis.reason);
                        maxSeverity = Math.max(maxSeverity, analysis.severity);
                    }
                }
                // 3. Scan for inline event handlers on common injection vector elements (img, svg, body, iframe)
                const dangerousElements = Array.from(document.querySelectorAll('img[onerror], svg[onload], iframe[srcdoc], body[onload]'));
                for (const el of dangerousElements) {
                    const attr = el.getAttribute('onerror') || el.getAttribute('onload') || el.getAttribute('srcdoc') || '';
                    if (/eval|atob|fetch|XMLHttpRequest|\.cookie/i.test(attr)) {
                        triggered = true;
                        detectedInjections.push(`Inline DOM event handler injection on <${el.tagName.toLowerCase()}>: ${attr.slice(0, 40)}...`);
                        maxSeverity = Math.max(maxSeverity, 5);
                    }
                }
            }
            evidence['detected_injections'] = detectedInjections;
            evidence['actual_value'] = triggered
                ? `Script injection threats detected (${detectedInjections.length}): ${detectedInjections.slice(0, 3).join(', ')}`
                : 'All DOM scripts and mutations verified compliant with origin and payload baselines';
            evidence['expected_value'] = 'All executed JavaScript must originate from authorized domains and contain no encoded eval payloads';
            evidence['threat_classification'] = triggered
                ? 'CRITICAL_SCRIPT_INJECTION_OR_XSS_DETECTED'
                : 'Clean DOM script environment';
            evidence['remediation_guidance'] = triggered
                ? 'Deploy strict Content Security Policy (CSP), remove unauthorized inline scripts, and audit third-party script sources'
                : 'No action required. DOM scripts compliant.';
        }
        catch (e) {
            evidence['error'] = `ScriptInjectionDetector error: ${e.message}`;
        }
        return {
            id: 'script_injection_detector',
            triggered,
            severity: triggered ? maxSeverity : 0,
            category: 'runtime',
            event: triggered ? 'script_injection_detected' : 'script_injection_verified_clean',
            confidence: 0.95,
            fpRiskTier: 'LOW',
            evasionDifficulty: 'MEDIUM',
            status: triggered ? 'FAILED' : 'PASSED',
            name: 'Script Injection Detector',
            evidence
        };
    }
    /**
     * Resets recorded mutation observer injections (useful for test isolations)
     */
    static clearObservedMutations() {
        OBSERVED_MUTATION_INJECTIONS.length = 0;
    }
}
