import { DetectorItem } from '../telemetry.js';
/**
 * MixedContentDetector: P4 Informational / Network Security Detector.
 *
 * Scans DOM resource URLs (scripts, stylesheets, iframes, images, forms) for unencrypted
 * `http://` resources loaded within a secure HTTPS origin context (Active/Passive Mixed Content).
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.03ms (DOM resource attribute sweep)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: None exfiltrated
 * - Evasion Limits: Mixed content fetched dynamically inside Web Workers requires CSP upgrade-insecure-requests.
 */
export declare class MixedContentDetector {
    static scan(): DetectorItem;
}
