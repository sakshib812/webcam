import { DetectorItem } from '../telemetry.js';
/**
 * MouseDynamicsDetector: P4 Informational / Behavioral Biometrics Detector.
 *
 * ⚖️ LEGAL REVIEW & PRIVACY COMPLIANCE GATE (GDPR Art. 9, CCPA, BIPA, India DPDP Act):
 * - Requires explicit user consent before activating mouse tracking (`requiresConsent: true`).
 * - ZERO coordinate logging in telemetry: Never transmits (x, y) coordinates or path trajectories.
 *   Only evaluates mathematical curvature entropy and acceleration delta statistics locally.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.03ms (Curvature cross-product computation on 50-point ring buffer)
 * - Execution Model: Event-driven ring buffer + on-demand synchronous scan
 * - Sensitive Data: Never exfiltrates screen positions or cursor path coordinates
 * - Evasion Limits: Sophisticated Bezier curve generation algorithms with human noise simulation.
 */
export interface MouseDynamicsOptions {
    consentGranted?: boolean;
}
export declare class MouseDynamicsDetector {
    static readonly requiresConsent = true;
    static initListener(options?: MouseDynamicsOptions): void;
    static scan(options?: MouseDynamicsOptions): DetectorItem;
    static recordSyntheticCollinearPoints(): void;
    static clearPoints(): void;
}
