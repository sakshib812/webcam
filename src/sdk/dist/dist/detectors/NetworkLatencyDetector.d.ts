import { DetectorItem } from '../telemetry.js';
/**
 * NetworkLatencyDetector: P4 Informational / Network Security Detector.
 *
 * Analyzes round-trip network request latency, TCP connect times, and performance timing metrics
 * to identify proxy relay delays, throttled debugging proxies (Burp Suite, Charles), or synthetic latency injection.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.02ms (Performance timing entry inspection)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: None exfiltrated
 * - Evasion Limits: Fast upstream proxies with minimal latency overhead cannot be differentiated from normal network jitter without backend RTT corroboration.
 */
export declare class NetworkLatencyDetector {
    static scan(): DetectorItem;
}
