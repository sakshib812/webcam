import { DetectorItem } from '../telemetry.js';
/**
 * TouchEventDetector: P4 Informational / Behavioral Biometrics Detector.
 *
 * ⚖️ LEGAL REVIEW & PRIVACY COMPLIANCE GATE (GDPR Art. 9, CCPA, BIPA, India DPDP Act):
 * - Requires explicit user consent before activating persistent touch event listeners (`requiresConsent: true`).
 * - ZERO coordinate tracking: Evaluates only touch physical properties (radiusX, radiusY, force, touchType).
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.02ms (Touch property inspection)
 * - Execution Model: Event-driven property audit + on-demand synchronous scan
 * - Sensitive Data: Never records touch locations or screen tap coordinates
 * - Evasion Limits: Desktop browser emulators that simulate realistic radiusX/radiusY touch properties.
 */
export interface TouchEventOptions {
    consentGranted?: boolean;
}
export declare class TouchEventDetector {
    static readonly requiresConsent = true;
    static initListeners(options?: TouchEventOptions): void;
    static scan(options?: TouchEventOptions): DetectorItem;
    static recordSyntheticTouch(isSynthetic: boolean): void;
    static resetTouchData(): void;
}
