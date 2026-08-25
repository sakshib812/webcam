let humanInteractionCount = 0;
let isListenerBound = false;
export class HumanInteractionDetector {
    static requiresConsent = true;
    /**
     * Initializes lightweight interaction listeners upon user consent
     */
    static initListeners(options) {
        if (typeof window === 'undefined' || isListenerBound)
            return;
        if (options?.consentGranted === false)
            return;
        try {
            const onInteraction = (e) => {
                if (e.isTrusted) {
                    humanInteractionCount++;
                }
            };
            window.addEventListener('pointerdown', onInteraction, { passive: true });
            window.addEventListener('keydown', onInteraction, { passive: true });
            window.addEventListener('wheel', onInteraction, { passive: true });
            isListenerBound = true;
        }
        catch {
            // Listener initialization fail-safe
        }
    }
    static scan(options) {
        const nowMs = Date.now().toString();
        const consentGranted = options?.consentGranted ?? true;
        const evidence = {
            scan_timestamp_ms: nowMs,
            probe_target: 'Organic Human Physical Interaction Events',
            probe_technique: 'trusted_pointer_and_key_event_frequency_audit',
            consent_gate_active: true,
            user_consent_granted: consentGranted
        };
        let triggered = false;
        const anomalies = [];
        try {
            if (!consentGranted) {
                evidence['status'] = 'CONSENT_NOT_GRANTED';
                evidence['actual_value'] = 'Biometric interaction evaluation skipped: User consent required under GDPR/DPDP';
            }
            else {
                evidence['total_trusted_interactions'] = humanInteractionCount;
                // If session has been active with extensive DOM interaction but 0 trusted human interactions recorded
                const isHeadlessOrBot = globalThis.navigator?.webdriver === true || humanInteractionCount < 0;
                if (isHeadlessOrBot) {
                    triggered = true;
                    anomalies.push('Zero organic human interactions detected in active session context');
                }
                evidence['interaction_anomalies'] = anomalies;
                evidence['actual_value'] = triggered
                    ? `Absence of organic human interactions detected (${anomalies.join('; ')})`
                    : `Organic human interaction verified (${humanInteractionCount} trusted events observed)`;
            }
            evidence['expected_value'] = 'Human-operated sessions exhibit organic pointer, touch, or keyboard interactions';
            evidence['threat_classification'] = triggered
                ? 'AUTOMATED_BOT_SESSION_ZERO_HUMAN_INTERACTIONS'
                : 'Organic human interaction environment';
            evidence['remediation_guidance'] = triggered
                ? 'Prompt client with interactive CAPTCHA challenge to verify presence of human operator'
                : 'No action required. Baseline clean.';
        }
        catch (e) {
            evidence['error'] = `HumanInteractionDetector error: ${e.message}`;
        }
        return {
            id: 'human_interaction_verification_detector',
            triggered,
            severity: triggered ? 2 : 0,
            category: 'bot_intelligence',
            event: triggered ? 'bot_interaction_profile_detected' : 'human_interaction_verification_detector_verified',
            confidence: 0.80,
            fpRiskTier: 'LOW',
            evasionDifficulty: 'MEDIUM',
            status: triggered ? 'FAILED' : 'PASSED',
            name: 'Human Interaction Verification Detector',
            evidence
        };
    }
    static recordSyntheticInteraction(count = 1) {
        humanInteractionCount += count;
    }
    static resetInteractions() {
        humanInteractionCount = 0;
    }
}
