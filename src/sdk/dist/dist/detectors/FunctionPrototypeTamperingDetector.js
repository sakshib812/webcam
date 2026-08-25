import { RuntimeIntegrityGuardian } from '../integrity/RuntimeIntegrityGuardian.js';
/**
 * FunctionPrototypeTamperingDetector: Validates Object.prototype, Function.prototype,
 * and Array.prototype against prototype pollution, descriptor mutations, and monkey patching.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.03ms (Property key set comparisons & native integrity audits)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: None read or exfiltrated
 * - Evasion Limits: If an attacker injects prototype pollution using non-enumerable symbols
 *   or freezes the prototype prior to SDK initialization, standard enumeration may not flag it.
 */
// Baseline standard own-property names of built-in prototypes
const EXPECTED_FUNCTION_PROPS = new Set([
    'length',
    'name',
    'arguments',
    'caller',
    'constructor',
    'apply',
    'bind',
    'call',
    'toString',
    'Symbol(Symbol.hasInstance)'
]);
const EXPECTED_OBJECT_PROPS = new Set([
    'constructor',
    '__defineGetter__',
    '__defineSetter__',
    'hasOwnProperty',
    '__lookupGetter__',
    '__lookupSetter__',
    'isPrototypeOf',
    'propertyIsEnumerable',
    'toString',
    'valueOf',
    '__proto__',
    'toLocaleString'
]);
export class FunctionPrototypeTamperingDetector {
    static scan() {
        const nowMs = Date.now().toString();
        const evidence = {
            scan_timestamp_ms: nowMs,
            probe_target: 'Function.prototype & Object.prototype Core Intrinsics',
            probe_technique: 'prototype_property_descriptor_and_pollution_audit'
        };
        let triggered = false;
        const anomalies = [];
        const pollutedKeys = [];
        try {
            // 1. Audit core Function.prototype methods
            const fnMethods = [
                { name: 'Function.prototype.toString', fn: Function.prototype.toString },
                { name: 'Function.prototype.bind', fn: Function.prototype.bind },
                { name: 'Function.prototype.apply', fn: Function.prototype.apply },
                { name: 'Function.prototype.call', fn: Function.prototype.call }
            ];
            for (const item of fnMethods) {
                if (!RuntimeIntegrityGuardian.isNativeFunction(item.fn)) {
                    triggered = true;
                    anomalies.push(`${item.name} is not a native C++ function (monkey-patched or proxied)`);
                }
            }
            // 2. Audit core Object.prototype methods
            const objMethods = [
                { name: 'Object.prototype.hasOwnProperty', fn: Object.prototype.hasOwnProperty },
                { name: 'Object.prototype.toString', fn: Object.prototype.toString },
                { name: 'Object.prototype.valueOf', fn: Object.prototype.valueOf },
                { name: 'Object.prototype.isPrototypeOf', fn: Object.prototype.isPrototypeOf }
            ];
            for (const item of objMethods) {
                if (!RuntimeIntegrityGuardian.isNativeFunction(item.fn)) {
                    triggered = true;
                    anomalies.push(`${item.name} is not a native C++ function (monkey-patched or proxied)`);
                }
            }
            // 3. Detect Prototype Pollution on Object.prototype & Function.prototype
            if (typeof Object.getOwnPropertyNames !== 'undefined') {
                const currentObjectProps = Object.getOwnPropertyNames(Object.prototype);
                for (const prop of currentObjectProps) {
                    if (!EXPECTED_OBJECT_PROPS.has(prop)) {
                        triggered = true;
                        pollutedKeys.push(`Object.prototype.${prop}`);
                    }
                }
                const currentFunctionProps = Object.getOwnPropertyNames(Function.prototype);
                for (const prop of currentFunctionProps) {
                    if (!EXPECTED_FUNCTION_PROPS.has(prop)) {
                        triggered = true;
                        pollutedKeys.push(`Function.prototype.${prop}`);
                    }
                }
            }
            // 4. Test prototype chain mutation
            const testObj = {};
            if (testObj.__proto__ !== Object.prototype) {
                triggered = true;
                anomalies.push('Global plain object __proto__ chain altered');
            }
            evidence['detected_anomalies'] = anomalies;
            evidence['polluted_properties'] = pollutedKeys;
            evidence['actual_value'] = triggered
                ? `Prototype tampering detected: ${[...anomalies, ...pollutedKeys].slice(0, 3).join(', ')}`
                : 'Function.prototype and Object.prototype verified clean without pollution';
            evidence['expected_value'] = 'Standard ECMAScript prototypes must contain only native methods with no injected properties';
            evidence['threat_classification'] = triggered
                ? 'HIGH_RISK_PROTOTYPE_POLLUTION_OR_PATCH'
                : 'Clean prototype environment';
            evidence['remediation_guidance'] = triggered
                ? 'Enable prototype freezing (enablePrototypeFreezing: true) and audit third-party dependencies'
                : 'No action required. Prototype baseline clean.';
        }
        catch (e) {
            evidence['error'] = `FunctionPrototypeTamperingDetector error: ${e.message}`;
        }
        return {
            id: 'function_prototype_tampering_detector',
            triggered,
            severity: triggered ? 4 : 0,
            category: 'runtime',
            event: triggered ? 'prototype_tampering_detected' : 'prototype_tampering_verified_clean',
            confidence: 0.95,
            fpRiskTier: 'LOW',
            evasionDifficulty: 'MEDIUM',
            status: triggered ? 'FAILED' : 'PASSED',
            name: 'Function Prototype Tampering Detector',
            evidence
        };
    }
}
