import { DetectorItem } from '../telemetry.js';
/**
 * SslValidationDetector: P4 Informational / Network Security Detector.
 *
 * Audits SSL/TLS transport context, verifies `window.isSecureContext` status,
 * and checks for insecure WebSocket connections created within a secure origin.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.01ms (Secure context flag and protocol check)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: None exfiltrated
 * - Evasion Limits: Localhost development testing environments are granted secure context equivalence.
 */
export declare class SslValidationDetector {
    static scan(): DetectorItem;
}
