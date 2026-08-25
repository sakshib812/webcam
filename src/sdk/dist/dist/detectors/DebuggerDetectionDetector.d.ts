import { DetectorItem } from '../telemetry.js';
/**
 * DebuggerDetectionDetector: Timing-based anti-debugging and breakpoint detection probe.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.02ms (High-resolution timer micro-benchmark)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: None read or exfiltrated
 * - Evasion Limits: Developers who disable breakpoints or attackers stepping through with
 *   automated CDP (Chrome DevTools Protocol) without pausing will not generate timing gaps.
 * - False Positive Considerations: Heavy CPU throttling or main thread event-loop delays
 *   could cause minor execution time spikes. The threshold is set conservatively (>100ms)
 *   and emits a low-severity informational signal (severity: 2) rather than blocking the host.
 */
export declare class DebuggerDetectionDetector {
    static scan(): DetectorItem;
}
