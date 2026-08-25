import { RuntimeIntegrityGuardian } from '../integrity/RuntimeIntegrityGuardian.js';
export class NativeApiOverrideDetector {
    static scan() {
        const nowMs = Date.now().toString();
        const audit = RuntimeIntegrityGuardian.auditRuntimeIntegrity();
        const evidence = {
            "scan_timestamp_ms": nowMs,
            "probe_target": "Global Native Function Intrinsics (fetch, JSON, crypto, defineProperty)",
            "probe_technique": "native_code_regex_verification_audit",
            "actual_value": audit.isClean
                ? "Global Native Function Strings verified clean in browser context"
                : `Tampered APIs detected (${audit.tamperedCount}): ${audit.tamperedApis.map(a => a.apiName).join(', ')}`,
            "expected_value": "All critical browser APIs must retain pristine native implementation",
            "threat_classification": audit.isClean ? "Clean browser environment" : "CRITICAL_API_MONKEY_PATCH_DETECTED",
            "remediation_guidance": audit.isClean ? "No action required. Baseline clean." : "Enforce strict CSP and inspect rogue extensions"
        };
        return {
            id: "native_api_override_detector",
            triggered: !audit.isClean,
            severity: audit.isClean ? 0 : 4,
            category: "runtime",
            event: audit.isClean ? "native_api_override_detector_verified" : "native_api_override_detected",
            evidence
        };
    }
}
