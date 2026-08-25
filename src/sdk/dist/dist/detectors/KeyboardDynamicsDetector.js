// Sliding window of inter-keystroke flight times in milliseconds (max 30 intervals)
const FLIGHT_TIME_INTERVALS = [];
let lastKeyDownTimestamp = 0;
let isKeyboardListenerBound = false;
export class KeyboardDynamicsDetector {
    static requiresConsent = true;
    static initListeners(options) {
        if (typeof window === 'undefined' || isKeyboardListenerBound)
            return;
        if (options?.consentGranted === false)
            return;
        try {
            window.addEventListener('keydown', (e) => {
                const now = Date.now();
                if (lastKeyDownTimestamp > 0) {
                    const flightTime = now - lastKeyDownTimestamp;
                    // Record only plausible intervals (<3000ms)
                    if (flightTime > 0 && flightTime < 3000) {
                        FLIGHT_TIME_INTERVALS.push(flightTime);
                        if (FLIGHT_TIME_INTERVALS.length > 30)
                            FLIGHT_TIME_INTERVALS.shift();
                    }
                }
                lastKeyDownTimestamp = now;
            }, { passive: true });
            isKeyboardListenerBound = true;
        }
        catch {
            // Fail-safe
        }
    }
    static scan(options) {
        const nowMs = Date.now().toString();
        const consentGranted = options?.consentGranted ?? true;
        const evidence = {
            scan_timestamp_ms: nowMs,
            probe_target: 'Keystroke Dwell & Inter-Key Flight Time Dynamics',
            probe_technique: 'keystroke_flight_time_statistical_variance_audit',
            consent_gate_active: true,
            user_consent_granted: consentGranted
        };
        let triggered = false;
        const anomalies = [];
        try {
            if (!consentGranted) {
                evidence['status'] = 'CONSENT_NOT_GRANTED';
                evidence['actual_value'] = 'Keyboard dynamics analysis skipped: User consent required under GDPR/DPDP';
            }
            else {
                const sampleCount = FLIGHT_TIME_INTERVALS.length;
                evidence['recorded_flight_intervals_count'] = sampleCount;
                if (sampleCount >= 6) {
                    // Calculate mean flight time
                    const sum = FLIGHT_TIME_INTERVALS.reduce((acc, val) => acc + val, 0);
                    const mean = sum / sampleCount;
                    // Calculate standard deviation / variance
                    const variance = FLIGHT_TIME_INTERVALS.reduce((acc, val) => acc + Math.pow(val - mean, 2), 0) / sampleCount;
                    const stdDev = Math.sqrt(variance);
                    evidence['flight_time_mean_ms'] = mean.toFixed(2);
                    evidence['flight_time_std_dev_ms'] = stdDev.toFixed(2);
                    // Robotic signature: Perfectly constant flight time (stdDev < 1.0ms) or instantaneous script bursts (mean < 5ms)
                    if (stdDev < 1.0) {
                        triggered = true;
                        anomalies.push(`Robotic input timing detected: Inter-keystroke variance is unnatural (stdDev: ${stdDev.toFixed(2)}ms)`);
                    }
                    else if (mean < 5.0) {
                        triggered = true;
                        anomalies.push(`Instantaneous programmatic keystroke flood detected (mean: ${mean.toFixed(2)}ms)`);
                    }
                }
                evidence['timing_anomalies'] = anomalies;
                evidence['actual_value'] = triggered
                    ? `Synthetic keyboard dynamics detected: ${anomalies.join('; ')}`
                    : sampleCount < 6
                        ? 'Insufficient keystroke cadence samples collected'
                        : 'Keystroke flight time variance exhibits organic human entropy';
            }
            evidence['expected_value'] = 'Human typing exhibits natural non-zero standard deviation in inter-key flight times';
            evidence['threat_classification'] = triggered
                ? 'SYNTHETIC_SCRIPTED_KEYBOARD_INJECTION_DETECTED'
                : 'Organic human keyboard typing environment';
            evidence['remediation_guidance'] = triggered
                ? 'Step up authentication or apply behavioral CAPTCHA challenge for rapid automated form submissions'
                : 'No action required. Baseline clean.';
        }
        catch (e) {
            evidence['error'] = `KeyboardDynamicsDetector error: ${e.message}`;
        }
        return {
            id: 'keyboard_dynamics_detector',
            triggered,
            severity: triggered ? 3 : 0,
            category: 'bot_intelligence',
            event: triggered ? 'robotic_keyboard_timing_detected' : 'keyboard_dynamics_detector_verified',
            confidence: 0.85,
            fpRiskTier: 'LOW',
            evasionDifficulty: 'MEDIUM',
            status: triggered ? 'FAILED' : 'PASSED',
            name: 'Keyboard Dynamics Detector',
            evidence
        };
    }
    static addFlightTimeSample(intervalMs) {
        FLIGHT_TIME_INTERVALS.push(intervalMs);
    }
    static clearSamples() {
        FLIGHT_TIME_INTERVALS.length = 0;
        lastKeyDownTimestamp = 0;
    }
}
