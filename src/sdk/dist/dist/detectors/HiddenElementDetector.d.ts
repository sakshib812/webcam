import { DetectorItem } from '../telemetry.js';
/**
 * HiddenElementDetector: P4 Informational / UI Security Detector.
 *
 * Identifies hidden DOM elements, zero-width inputs, and invisible iframe overlays
 * placed outside the viewport or with transparent opacity used in clickjacking or credential harvesting.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.04ms (DOM input & iframe style audit)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: None read or exfiltrated
 * - Evasion Limits: Highly dynamic opacity toggling immediately before user click
 *   requires ongoing pointer event interception.
 */
export declare class HiddenElementDetector {
    static scan(): DetectorItem;
}
