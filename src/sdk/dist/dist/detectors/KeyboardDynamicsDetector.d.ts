import { DetectorItem } from '../telemetry.js';
/**
 * KeyboardDynamicsDetector: P4 Informational / Behavioral Biometrics Detector.
 *
 * ⚖️ LEGAL REVIEW & PRIVACY COMPLIANCE GATE (GDPR Art. 9, CCPA, BIPA, India DPDP Act):
 * - Requires explicit user consent (`requiresConsent: true`).
 * - STRICT PRIVACY ENFORCEMENT: Never reads, logs, or stores raw keystrokes, ASCII characters,
 *   or keyCode/key values. ONLY computes numerical timing intervals (inter-keystroke flight times).
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.03ms (Statistical variance calculation on sliding float window)
 * - Execution Model: Event-driven interval logging + on-demand synchronous scan
 * - Sensitive Data: ZERO character or key data recorded. Only interval float arrays.
 * - Evasion Limits: Bots that inject randomized Gaussian timing delays between send_keys calls.
 */
export interface KeyboardDynamicsOptions {
    consentGranted?: boolean;
}
export declare class KeyboardDynamicsDetector {
    static readonly requiresConsent = true;
    static initListeners(options?: KeyboardDynamicsOptions): void;
    static scan(options?: KeyboardDynamicsOptions): DetectorItem;
    static addFlightTimeSample(intervalMs: number): void;
    static clearSamples(): void;
}
