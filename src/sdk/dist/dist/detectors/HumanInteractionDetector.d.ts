import { DetectorItem } from '../telemetry.js';
/**
 * HumanInteractionDetector: P4 Informational / Behavioral Biometrics Detector.
 *
 * ⚖️ LEGAL REVIEW & PRIVACY COMPLIANCE GATE (GDPR Art. 9, CCPA, BIPA, India DPDP Act):
 * - Requires explicit user consent before activating persistent biometric tracking (`requiresConsent: true`).
 * - ZERO raw event payload logging: Only aggregate interaction counts and presence flags are evaluated.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.02ms (Event counter inspection)
 * - Execution Model: Event-driven counter accumulation with on-demand synchronous scan
 * - Sensitive Data: Never records input data, cursor coordinates, or target elements
 * - Evasion Limits: Bots that simulate fake random pointerdown events can satisfy interaction counts.
 */
export interface BiometricConsentOptions {
    consentGranted?: boolean;
}
export declare class HumanInteractionDetector {
    static readonly requiresConsent = true;
    /**
     * Initializes lightweight interaction listeners upon user consent
     */
    static initListeners(options?: BiometricConsentOptions): void;
    static scan(options?: BiometricConsentOptions): DetectorItem;
    static recordSyntheticInteraction(count?: number): void;
    static resetInteractions(): void;
}
