import { DetectorItem } from '../telemetry.js';
/**
 * ExtensionPermissionAbuseDetector: P4 Informational / Form Security Detector.
 *
 * Audits sensitive form fields (password, credit card, OTP, PIN) for unauthorized
 * value reading closures, rogue event listeners, or shadow property interceptors.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.03ms (Targeted input element selector sweep)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: Never reads or records field contents; only checks listeners and descriptor integrity
 * - Evasion Limits: If an extension content script injects an isolated world listener that doesn't
 *   pollute the main execution realm's property descriptors, detection relies on mutation observer alerts.
 */
export declare class ExtensionPermissionAbuseDetector {
    static scan(): DetectorItem;
}
