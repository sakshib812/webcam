import { DetectorItem } from '../telemetry.js';
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
export declare class UserAgentTamperingDetector {
    static scan(): DetectorItem;
}
