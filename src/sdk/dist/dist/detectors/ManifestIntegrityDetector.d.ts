import { DetectorItem } from '../telemetry.js';
/**
 * ManifestIntegrityDetector: P4 Informational / Application Integrity Detector.
 *
 * Validates Web App Manifest (`<link rel="manifest">`) link tags, checks origin
 * conformity, and flags malicious URI schemes or untrusted third-party manifest hosts.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.02ms (Single DOM link query)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: None read or exfiltrated
 * - Evasion Limits: Manifests loaded dynamically via service worker fetch hooks
 *   require service worker network interceptor audits.
 */
export declare class ManifestIntegrityDetector {
    static scan(): DetectorItem;
}
