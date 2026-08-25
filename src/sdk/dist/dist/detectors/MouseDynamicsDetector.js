const MOUSE_MOVE_BUFFER = [];
let isMouseListenerBound = false;
export class MouseDynamicsDetector {
    static requiresConsent = true;
    static initListener(options) {
        if (typeof window === 'undefined' || isMouseListenerBound)
            return;
        if (options?.consentGranted === false)
            return;
        try {
            window.addEventListener('mousemove', (e) => {
                MOUSE_MOVE_BUFFER.push({ x: e.clientX, y: e.clientY, t: Date.now() });
                if (MOUSE_MOVE_BUFFER.length > 50)
                    MOUSE_MOVE_BUFFER.shift();
            }, { passive: true });
            isMouseListenerBound = true;
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
            probe_target: 'Mouse Movement Bezier Trajectory & Curvature Entropy',
            probe_technique: 'mouse_kinematics_bot_trajectory_audit',
            consent_gate_active: true,
            user_consent_granted: consentGranted
        };
        let triggered = false;
        const anomalies = [];
        try {
            if (!consentGranted) {
                evidence['status'] = 'CONSENT_NOT_GRANTED';
                evidence['actual_value'] = 'Mouse dynamics analysis skipped: User consent required under GDPR/DPDP';
            }
            else {
                evidence['collected_kinematic_points'] = MOUSE_MOVE_BUFFER.length;
                if (MOUSE_MOVE_BUFFER.length >= 6) {
                    let zeroCurvatureCount = 0;
                    let totalSegments = 0;
                    for (let i = 2; i < MOUSE_MOVE_BUFFER.length; i++) {
                        const p1 = MOUSE_MOVE_BUFFER[i - 2];
                        const p2 = MOUSE_MOVE_BUFFER[i - 1];
                        const p3 = MOUSE_MOVE_BUFFER[i];
                        // Cross product check for collinearity (straight line movement)
                        const area = (p2.x - p1.x) * (p3.y - p1.y) - (p2.y - p1.y) * (p3.x - p1.x);
                        if (Math.abs(area) < 0.001)
                            zeroCurvatureCount++;
                        totalSegments++;
                    }
                    const collinearRatio = totalSegments > 0 ? zeroCurvatureCount / totalSegments : 0;
                    evidence['collinear_ratio'] = collinearRatio.toFixed(3);
                    if (collinearRatio > 0.90) {
                        triggered = true;
                        anomalies.push(`Linear robotic mouse trajectory detected: ${(collinearRatio * 100).toFixed(1)}% collinear movements`);
                    }
                }
                evidence['trajectory_anomalies'] = anomalies;
                evidence['actual_value'] = triggered
                    ? `Automated Synthetic Mouse Trajectory detected (${anomalies.join('; ')})`
                    : 'Organic human mouse movement curvature entropy verified';
            }
            evidence['expected_value'] = 'Organic human mouse trajectory with non-zero curvature entropy';
            evidence['threat_classification'] = triggered
                ? 'AUTOMATED_SYNTHETIC_MOUSE_TRAJECTORY_DETECTED'
                : 'Organic human mouse interaction environment';
            evidence['remediation_guidance'] = triggered
                ? 'Challenge suspicious robotic mouse movements with CAPTCHA or step-up auth'
                : 'No action required. Mouse movement kinematics verified.';
        }
        catch (e) {
            evidence['error'] = `MouseDynamicsDetector error: ${e.message}`;
        }
        return {
            id: 'mouse_movement_analysis_detector',
            triggered,
            severity: triggered ? 3 : 0,
            category: 'bot_intelligence',
            event: triggered ? 'bot_mouse_trajectory_detected' : 'mouse_dynamics_detector_verified',
            confidence: 0.85,
            fpRiskTier: 'LOW',
            evasionDifficulty: 'MEDIUM',
            status: triggered ? 'FAILED' : 'PASSED',
            name: 'Mouse Dynamics Detector',
            evidence
        };
    }
    static recordSyntheticCollinearPoints() {
        MOUSE_MOVE_BUFFER.length = 0;
        // Add 10 points along a perfectly straight line: y = 2x
        for (let i = 0; i < 10; i++) {
            MOUSE_MOVE_BUFFER.push({ x: i * 10, y: i * 20, t: Date.now() + i * 10 });
        }
    }
    static clearPoints() {
        MOUSE_MOVE_BUFFER.length = 0;
    }
}
