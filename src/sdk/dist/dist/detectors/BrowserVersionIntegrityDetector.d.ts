import { DetectorItem } from '../telemetry.js';
/**
 * BrowserVersionIntegrityDetector: P4 Informational / Environment Security Detector.
 *
 * Cross-checks `navigator.userAgentData` (Client Hints) brands and versions against
 * `navigator.userAgent` and engine features to identify contradictory version spoofing.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.02ms (String extraction and regex comparison)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: None exfiltrated
 * - Evasion Limits: If Client Hints API is entirely absent (e.g. Firefox/Safari), version audit relies on UA pattern parsing.
 */
export declare class BrowserVersionIntegrityDetector {
    static scan(): DetectorItem;
}
