import { DetectorItem } from '../telemetry.js';
/**
 * BrowserCapabilitySpoofingDetector: P4 Informational / Environment Security Detector.
 *
 * Detects inconsistencies between reported browser engine claims (in userAgent/vendor)
 * and actual Web API features supported by the underlying JavaScript rendering engine.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.02ms (Direct property and feature checks)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: None exfiltrated
 * - Evasion Limits: Custom Chromium forks with modified user-agents may trigger informational mismatches.
 */
export declare class BrowserCapabilitySpoofingDetector {
    static scan(): DetectorItem;
}
