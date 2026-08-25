import { RuntimeIntegrityGuardian } from '../integrity/RuntimeIntegrityGuardian.js';
/**
 * NativeApiOverrideDetector: Early-baseline & active integrity verification for native browser APIs.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.04ms (Synchronous reference & descriptor verification over 12 native primitives)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: None read or exfiltrated
 * - Evasion Limits: If an attacker injects a script in document <head> BEFORE the SecureShield SDK script tag
 *   evaluates, the attacker can hook native functions and spoof Function.prototype.toString before the SDK's
 *   baseline is recorded.
 */
// Capture early reference baseline at module evaluation time
const BASELINE_PRIMITIVES = {};
try {
    const globalScope = typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : (typeof self !== 'undefined' ? self : {}));
    const docScope = typeof document !== 'undefined' ? document : null;
    const eventTargetScope = typeof EventTarget !== 'undefined' && EventTarget.prototype ? EventTarget.prototype : null;
    const cryptoScope = typeof crypto !== 'undefined' ? crypto : null;
    const primitives = [
        [globalScope, 'fetch'],
        [globalScope, 'setTimeout'],
        [globalScope, 'setInterval'],
        [globalScope, 'WebSocket'],
        [typeof XMLHttpRequest !== 'undefined' ? globalScope : null, 'XMLHttpRequest'],
        [docScope, 'createElement'],
        [eventTargetScope, 'addEventListener'],
        [eventTargetScope, 'removeEventListener'],
        [cryptoScope, 'getRandomValues'],
        [typeof JSON !== 'undefined' ? JSON : null, 'stringify'],
        [typeof JSON !== 'undefined' ? JSON : null, 'parse'],
        [typeof Object !== 'undefined' ? Object : null, 'defineProperty']
    ];
    for (const [target, prop] of primitives) {
        if (target && target[prop]) {
            BASELINE_PRIMITIVES[prop] = {
                target,
                prop,
                ref: target[prop],
                descriptor: Object.getOwnPropertyDescriptor(target, prop)
            };
        }
    }
}
catch {
    // Fail-safe baseline initialization
}
export class NativeApiOverrideDetector {
    static scan() {
        const nowMs = Date.now().toString();
        const evidence = {
            scan_timestamp_ms: nowMs,
            probe_target: 'Global Native Browser Primitives (fetch, XHR, createElement, addEventListener)',
            probe_technique: 'baseline_identity_and_native_code_signature_audit',
            audited_primitives_count: Object.keys(BASELINE_PRIMITIVES).length
        };
        let triggered = false;
        const overrides = [];
        const descriptorAnomalies = [];
        try {
            // 1. Audit RuntimeIntegrityGuardian primitives
            const integrityReport = RuntimeIntegrityGuardian.auditRuntimeIntegrity();
            if (!integrityReport.isClean) {
                triggered = true;
                for (const item of integrityReport.tamperedApis) {
                    overrides.push(`${item.apiName} (RuntimeIntegrityGuardian failed: ${item.reason})`);
                }
            }
            // 2. Audit baseline reference identity & string representation
            for (const [prop, baseline] of Object.entries(BASELINE_PRIMITIVES)) {
                try {
                    const currentTarget = baseline.target;
                    const currentRef = currentTarget ? currentTarget[prop] : null;
                    if (!currentRef) {
                        triggered = true;
                        overrides.push(`${prop} (Primitive missing or deleted)`);
                        continue;
                    }
                    // Reference Identity check: has reference mutated since module load?
                    if (baseline.ref && currentRef !== baseline.ref) {
                        triggered = true;
                        overrides.push(`${prop} (Reference mutated after SDK baseline capture)`);
                    }
                    // String representation check
                    const isNative = RuntimeIntegrityGuardian.isNativeFunction(currentRef);
                    const wasBaselineNative = baseline.ref ? RuntimeIntegrityGuardian.isNativeFunction(baseline.ref) : false;
                    if (!isNative && wasBaselineNative) {
                        triggered = true;
                        overrides.push(`${prop} (Lost [native code] signature)`);
                    }
                    else if (Object.prototype.hasOwnProperty.call(currentRef, 'toString')) {
                        triggered = true;
                        overrides.push(`${prop} (Shadow own-property toString override detected)`);
                    }
                    // Property Descriptor check
                    if (currentTarget) {
                        const currentDesc = Object.getOwnPropertyDescriptor(currentTarget, prop);
                        if (currentDesc) {
                            if (currentDesc.get || currentDesc.set) {
                                triggered = true;
                                descriptorAnomalies.push(`${prop} (Getter/Setter trap installed on native property)`);
                            }
                        }
                    }
                }
                catch (itemErr) {
                    overrides.push(`${prop} (Error auditing: ${itemErr.message})`);
                }
            }
            evidence['detected_overrides'] = overrides;
            evidence['descriptor_anomalies'] = descriptorAnomalies;
            evidence['actual_value'] = triggered
                ? `Tampered APIs detected (${overrides.length}): ${overrides.slice(0, 3).join(', ')}`
                : 'All audited native APIs match pristine native function baselines';
            evidence['expected_value'] = 'All native browser APIs must retain pristine C++ engine function pointers';
            evidence['threat_classification'] = triggered
                ? 'CRITICAL_NATIVE_API_HOOK_DETECTED'
                : 'Clean native API runtime';
            evidence['remediation_guidance'] = triggered
                ? 'Inspect unauthorized third-party scripts, browser extensions, or proxy injectors'
                : 'No action required. Native API baseline clean.';
        }
        catch (e) {
            evidence['error'] = `NativeApiOverrideDetector execution error: ${e.message}`;
        }
        return {
            id: 'native_api_override_detector',
            triggered,
            severity: triggered ? 4 : 0, // High severity risk signal
            category: 'runtime',
            event: triggered ? 'native_api_override_detected' : 'native_api_override_verified_clean',
            confidence: 0.95,
            fpRiskTier: 'LOW',
            evasionDifficulty: 'MEDIUM',
            status: triggered ? 'FAILED' : 'PASSED',
            name: 'Native API Override Detector',
            evidence
        };
    }
}
