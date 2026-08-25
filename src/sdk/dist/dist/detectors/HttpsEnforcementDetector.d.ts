import { DetectorItem } from '../telemetry.js';
/**
 * HttpsEnforcementDetector: P4 Informational / Network Security Detector.
 *
 * Verifies that the web application is running over encrypted transport (HTTPS)
 * and flags unencrypted HTTP sessions that expose user credentials to MITM interception.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.01ms (Simple protocol and hostname check)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: None exfiltrated
 * - Evasion Limits: Local loopback hosts (localhost, 127.0.0.1) are granted development exemptions.
 */
export declare class HttpsEnforcementDetector {
    static scan(): DetectorItem;
}
