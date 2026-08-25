import { DetectorItem } from '../telemetry.js';
/**
 * SessionAnomalyDetector: P4 Informational / Bot Intelligence & Session Detector.
 *
 * Audits tab duplication, multiple conflicting session IDs in the same origin,
 * or concurrent session collision markers indicative of automated session hijacking or cloning.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.02ms (Storage session token and lock check)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: None exfiltrated; session IDs are hashed/redacted.
 * - Evasion Limits: Multi-tab sessions opened in isolated incognito profiles cannot be correlated locally.
 */
export declare class SessionAnomalyDetector {
    static scan(): DetectorItem;
}
