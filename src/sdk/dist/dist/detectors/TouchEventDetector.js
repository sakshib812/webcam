let lastTouchPhysicalIntegrity = null;
let isTouchListenerBound = false;
export class TouchEventDetector {
    static requiresConsent = true;
    static initListeners(options) {
        if (typeof window === 'undefined' || isTouchListenerBound)
            return;
        if (options?.consentGranted === false)
            return;
        try {
            window.addEventListener('touchstart', (e) => {
                if (e.touches && e.touches.length > 0) {
                    const touch = e.touches[0];
                    const radiusX = touch.radiusX || 0;
                    const radiusY = touch.radiusY || 0;
                    const force = touch.force || 0;
                    // Touch events dispatched by desktop devtools emulation or synthetic dispatchEvent often have 0 radius and 0 force
                    const isSynthetic = !e.isTrusted || (radiusX === 0 && radiusY === 0 && force === 0);
                    lastTouchPhysicalIntegrity = {
                        radiusValid: radiusX > 0 || radiusY > 0,
                        forceValid: force >= 0,
                        isSynthetic
                    };
                }
            }, { passive: true });
            isTouchListenerBound = true;
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
            probe_target: 'Touch Event Radius & Physical Force Multi-Point Metrics',
            probe_technique: 'touch_radius_force_multi_point_audit',
            consent_gate_active: true,
            user_consent_granted: consentGranted
        };
        let triggered = false;
        const anomalies = [];
        try {
            if (!consentGranted) {
                evidence['status'] = 'CONSENT_NOT_GRANTED';
                evidence['actual_value'] = 'Touch event biometric analysis skipped: User consent required under GDPR/DPDP';
            }
            else {
                const isTouchDevice = typeof window !== 'undefined' && ('ontouchstart' in window || navigator.maxTouchPoints > 0);
                evidence['is_touch_device'] = isTouchDevice;
                evidence['max_touch_points'] = typeof navigator !== 'undefined' ? navigator.maxTouchPoints : 0;
                if (lastTouchPhysicalIntegrity) {
                    evidence['last_touch_synthetic_flag'] = lastTouchPhysicalIntegrity.isSynthetic;
                    if (lastTouchPhysicalIntegrity.isSynthetic) {
                        triggered = true;
                        anomalies.push('Synthetic or emulated touch event detected (Zero contact radius and unverified physical force)');
                    }
                }
                evidence['touch_anomalies'] = anomalies;
                evidence['actual_value'] = triggered
                    ? `Synthetic touch events detected: ${anomalies.join('; ')}`
                    : 'Touch Event Radius & Force Points verified clean in browser context';
            }
            evidence['expected_value'] = 'Touch events on mobile devices must exhibit genuine non-zero contact geometry';
            evidence['threat_classification'] = triggered
                ? 'EMULATED_OR_SYNTHETIC_TOUCH_INJECTION_DETECTED'
                : 'Clean browser environment';
            evidence['remediation_guidance'] = triggered
                ? 'Verify device integrity for mobile device spoofing or automated touch emulation'
                : 'No action required. Baseline clean.';
        }
        catch (e) {
            evidence['error'] = `TouchEventDetector error: ${e.message}`;
        }
        return {
            id: 'touch_event_analysis_detector',
            triggered,
            severity: triggered ? 2 : 0,
            category: 'bot_intelligence',
            event: triggered ? 'synthetic_touch_event_detected' : 'touch_event_analysis_detector_verified',
            confidence: 0.80,
            fpRiskTier: 'LOW',
            evasionDifficulty: 'MEDIUM',
            status: triggered ? 'FAILED' : 'PASSED',
            name: 'Touch Event Analysis Detector',
            evidence
        };
    }
    static recordSyntheticTouch(isSynthetic) {
        lastTouchPhysicalIntegrity = {
            radiusValid: !isSynthetic,
            forceValid: !isSynthetic,
            isSynthetic
        };
    }
    static resetTouchData() {
        lastTouchPhysicalIntegrity = null;
    }
}
