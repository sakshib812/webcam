import { DetectorItem } from '../telemetry.js';
/**
 * UiOverlayDetector: P4 Informational / UI Security Detector.
 *
 * Detects transparent, fixed, or absolute overlay elements (`opacity: 0`, `z-index: >1000`)
 * layered over interactive buttons and form inputs designed for UI tapjacking or clickjacking.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.04ms (Fixed/Absolute element geometry check)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: None read or exfiltrated
 * - Evasion Limits: Overlays added dynamically upon hover and immediately removed
 *   after click may evade discrete polling scans.
 */
export declare class UiOverlayDetector {
    static scan(): DetectorItem;
}
