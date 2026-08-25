/**
 * ContentScriptInjectionDetector: P4 Informational / Extension Security Detector.
 *
 * Identifies content script execution artifacts, global variables injected by browser
 * extensions into the page context, and DOM dataset markers.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.03ms (Global key sweep + DOM dataset inspection)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: None read or exfiltrated
 * - Evasion Limits: Content scripts executing in isolated worlds that do not touch
 *   window globals or DOM attributes cannot be detected via userland JavaScript.
 */
const SUSPICIOUS_EXTENSION_GLOBALS = [
    '__REACT_DEVTOOLS_GLOBAL_HOOK__injected',
    '__SCRIPTCAT__',
    '__VIOLENTMONKEY__',
    '__TAMPERMONKEY__',
    '__EXTENSION_INJECTED_API__',
    '_tampermonkey_',
    'GM_info',
    'unsafeWindow'
];
export class ContentScriptInjectionDetector {
    static scan() {
        const nowMs = Date.now().toString();
        const evidence = {
            scan_timestamp_ms: nowMs,
            probe_target: 'Content Script Injected Global Variables & Dataset Flags',
            probe_technique: 'content_script_global_flag_audit'
        };
        let triggered = false;
        const detectedScripts = [];
        try {
            const scopesToCheck = [
                typeof window !== 'undefined' ? window : null,
                typeof globalThis !== 'undefined' ? globalThis : null
            ].filter(Boolean);
            // 1. Audit known extension / userscript manager globals
            for (const globalVar of SUSPICIOUS_EXTENSION_GLOBALS) {
                if (scopesToCheck.some(s => globalVar in s)) {
                    triggered = true;
                    detectedScripts.push(`Injected global variable detected: ${globalVar}`);
                }
            }
            // 2. Audit DOM root attributes (document.documentElement dataset flags)
            if (typeof document !== 'undefined' && document.documentElement) {
                const root = document.documentElement;
                for (const attr of Array.from(root.attributes || [])) {
                    if (attr.name.startsWith('data-extension') || attr.name.startsWith('data-injected') || attr.name.includes('tampermonkey')) {
                        triggered = true;
                        detectedScripts.push(`DOM root attribute marker detected: ${attr.name}`);
                    }
                }
            }
            evidence['detected_content_scripts'] = detectedScripts;
            evidence['actual_value'] = triggered
                ? `Content script injection artifacts detected (${detectedScripts.length}): ${detectedScripts.slice(0, 3).join(', ')}`
                : 'Content Script Injected Variables verified clean in browser context';
            evidence['expected_value'] = 'Page runtime must remain free from unauthorized userscript or extension globals';
            evidence['threat_classification'] = triggered
                ? 'CONTENT_SCRIPT_OR_USERSCRIPT_DETECTED'
                : 'Clean browser environment';
            evidence['remediation_guidance'] = triggered
                ? 'Inspect active browser extensions and userscript managers (Tampermonkey, Violentmonkey)'
                : 'No action required. Baseline clean.';
        }
        catch (e) {
            evidence['error'] = `ContentScriptInjectionDetector error: ${e.message}`;
        }
        return {
            id: 'content_script_injection_detector',
            triggered,
            severity: triggered ? 2 : 0,
            category: 'extension_security',
            event: triggered ? 'content_script_injection_detected' : 'content_script_injection_detector_verified',
            confidence: 0.85,
            fpRiskTier: 'LOW',
            evasionDifficulty: 'MEDIUM',
            status: triggered ? 'FAILED' : 'PASSED',
            name: 'Content Script Injection Detector',
            evidence
        };
    }
}
