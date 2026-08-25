import { RuntimeIntegrityGuardian } from '../integrity/RuntimeIntegrityGuardian.js';
/**
 * ConsoleTamperingDetector: Validates the global `console` object methods against
 * unauthorized wrapping, log silencing, or adversarial interception.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.02ms (String signature and prototype checks across 6 console methods)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: None read or exfiltrated
 * - Evasion Limits: If a build pipeline intentionally replaces console methods (e.g. Terser /
 *   drop_console plugin) with custom no-ops before SDK loads, it will be flagged as tampered.
 *   Teams using build-time console stripping can add this detector to `disabledDetectors`.
 */
// Baseline console references at module evaluation time
const BASELINE_CONSOLE = {};
try {
    if (typeof console !== 'undefined') {
        const methods = ['log', 'warn', 'error', 'debug', 'info', 'trace', 'table'];
        for (const m of methods) {
            if (console[m]) {
                BASELINE_CONSOLE[m] = console[m];
            }
        }
    }
}
catch {
    // Fail-safe baseline capture
}
export class ConsoleTamperingDetector {
    static scan() {
        const nowMs = Date.now().toString();
        const evidence = {
            scan_timestamp_ms: nowMs,
            probe_target: 'Global window.console (log, warn, error, debug, info)',
            probe_technique: 'native_code_signature_and_reference_audit'
        };
        let triggered = false;
        const tamperedMethods = [];
        try {
            if (typeof console === 'undefined') {
                triggered = true;
                tamperedMethods.push('console (Global object completely undefined or stripped)');
            }
            else {
                const methodsToCheck = ['log', 'warn', 'error', 'debug', 'info'];
                for (const method of methodsToCheck) {
                    const fn = console[method];
                    if (!fn) {
                        triggered = true;
                        tamperedMethods.push(`console.${method} (Method missing/deleted)`);
                        continue;
                    }
                    // Check 1: Reference mutation since module load
                    if (BASELINE_CONSOLE[method] && fn !== BASELINE_CONSOLE[method]) {
                        triggered = true;
                        tamperedMethods.push(`console.${method} (Reference mutated after SDK baseline capture)`);
                    }
                    // Check 2: Native code signature verification
                    const isNative = RuntimeIntegrityGuardian.isNativeFunction(fn);
                    if (!isNative) {
                        triggered = true;
                        tamperedMethods.push(`console.${method} (Non-native implementation / wrapped closure)`);
                    }
                    // Check 3: Check for shadow own-property toString override
                    if (Object.prototype.hasOwnProperty.call(fn, 'toString')) {
                        triggered = true;
                        tamperedMethods.push(`console.${method} (Custom shadow toString override detected)`);
                    }
                }
            }
            evidence['tampered_methods'] = tamperedMethods;
            evidence['actual_value'] = triggered
                ? `Console tampering detected: ${tamperedMethods.join(', ')}`
                : 'All console methods verified native and unaltered';
            evidence['expected_value'] = 'Standard console logging methods must retain native browser implementations';
            evidence['threat_classification'] = triggered
                ? 'CONSOLE_OBJECT_TAMPERING_OR_SILENCING'
                : 'Clean console logging environment';
            evidence['remediation_guidance'] = triggered
                ? 'Inspect third-party scripts or extensions that intercept console telemetry, or configure disabledDetectors if intentionally stripped'
                : 'No action required. Console methods verified clean.';
        }
        catch (e) {
            evidence['error'] = `ConsoleTamperingDetector error: ${e.message}`;
        }
        return {
            id: 'console_tampering_detector',
            triggered,
            severity: triggered ? 2 : 0, // Medium/informational severity
            category: 'code',
            event: triggered ? 'console_object_tampered' : 'console_object_verified_clean',
            confidence: 0.90,
            fpRiskTier: 'LOW',
            evasionDifficulty: 'LOW',
            status: triggered ? 'FAILED' : 'PASSED',
            name: 'Console Tampering Detector',
            evidence
        };
    }
}
