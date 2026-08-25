import { DetectorItem } from '../telemetry.js';
/**
 * TimeManipulationDetector: P2 Medium Regulatory Baseline Detector.
 *
 * Compares wall-clock time (`Date.now()`) drift against monotonic high-resolution
 * timers (`performance.now()`) and verified server timestamps to identify client
 * system clock tampering, replay attack preparation, and token expiration bypass attempts.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.01ms (Simple arithmetic subtraction between timestamps)
 * - Execution Model: On-demand synchronous comparison
 * - Sensitive Data: None read or exfiltrated
 * - Evasion Limits: If a client's system clock was already distorted before the browser
 *   tab was opened AND no server timestamp anchor has been received yet, monotonic
 *   performance.now() only catches clock adjustments that occur WHILE the session is active.
 *   Receiving an anchor via `setServerTimeAnchor()` provides true global clock skew verification.
 */
export interface TimeManipulationOptions {
    maxAllowedDriftMs?: number;
}
export declare class TimeManipulationDetector {
    private static serverAnchorTimeMs;
    private static serverAnchorPerfMs;
    /**
     * Anchors a trusted server timestamp (e.g. from backend attestation or policy response)
     */
    static setServerTimeAnchor(serverTimestampMs: number): void;
    static scan(options?: TimeManipulationOptions): DetectorItem;
}
