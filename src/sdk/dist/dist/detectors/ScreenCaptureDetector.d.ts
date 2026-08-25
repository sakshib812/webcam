import { DetectorItem } from '../telemetry.js';
/**
 * ScreenCaptureDetector: P4 Informational / UI Security Detector.
 *
 * Detects active screen capture APIs (`navigator.mediaDevices.getDisplayMedia`),
 * screen sharing sessions, and unauthorized capture attempts during sensitive user operations.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.02ms (API inspection and stream check)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: None read or recorded
 * - Evasion Limits: OS-level screen capture software (OBS, native OS snipping tools)
 *   that does not invoke WebRTC `getDisplayMedia` cannot be detected directly by browser JS.
 */
export declare class ScreenCaptureDetector {
    static scan(): DetectorItem;
}
