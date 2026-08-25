import { DetectorItem } from '../telemetry.js';
/**
 * ClientConfigTamperingDetector: P4 Informational / Application Integrity Detector.
 *
 * Audits client-side global configuration stores (`window.__CONFIG__`, `window.__ENV__`, `window.SecureShieldConfig`)
 * for unexpected runtime property mutation, prototype injection, or tampering with critical endpoint URLs.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.02ms (Config store property audit)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: Config values are audited for structure without exfiltrating secrets
 * - Evasion Limits: If config stores are modified before SDK initialization, baseline freezing is recommended.
 */
export declare class ClientConfigTamperingDetector {
    static scan(): DetectorItem;
}
