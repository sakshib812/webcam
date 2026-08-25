import { DetectorItem } from '../telemetry.js';
/**
 * RuntimeFunctionHookDetector: Detects dynamic function wrapping, proxying,
 * and stealth monkey patching across critical JavaScript runtime entrypoints.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.04ms (String signature and toString-of-toString recursion checks)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: None read or exfiltrated
 * - Evasion Limits: A sophisticated attacker could implement a transparent Proxy that returns
 *   pristine toString results, catches all trap handler evaluations, and patches Function.prototype.toString.
 *   Note: In a pure client-side environment without multi-realm iframe isolation, an identical Proxy
 *   wrapper with perfect trap reflection cannot be 100% distinguished from native code.
 */
export declare class RuntimeFunctionHookDetector {
    static scan(): DetectorItem;
}
