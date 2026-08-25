export class MouseDynamicsDetector {
    static moveEvents = [];
    static initListener() {
        if (typeof window !== "undefined") {
            window.addEventListener("mousemove", (e) => {
                this.moveEvents.push({ x: e.clientX, y: e.clientY, t: Date.now() });
                if (this.moveEvents.length > 50)
                    this.moveEvents.shift();
            });
        }
    }
    static scan() {
        const nowMs = Date.now().toString();
        const evidence = {
            "scan_timestamp_ms": nowMs,
            "probe_target": "Mouse Movement Bezier Trajectory & Curvature Entropy",
            "probe_technique": "mouse_kinematics_bot_trajectory_audit",
            "expected_value": "Organic human mouse trajectory with non-zero curvature entropy",
            "threat_classification": "Automated Synthetic Mouse Trajectory (Linear Bot Injection)",
            "remediation_guidance": "Challenge suspicious robotic mouse movements with CAPTCHA or step-up auth"
        };
        let triggered = false;
        let actualVal = "Organic human mouse movement entropy verified";
        if (this.moveEvents.length >= 5) {
            let zeroCurvatureCount = 0;
            for (let i = 2; i < this.moveEvents.length; i++) {
                const p1 = this.moveEvents[i - 2];
                const p2 = this.moveEvents[i - 1];
                const p3 = this.moveEvents[i];
                // Cross product check for collinearity (straight line movement)
                const area = (p2.x - p1.x) * (p3.y - p1.y) - (p2.y - p1.y) * (p3.x - p1.x);
                if (Math.abs(area) < 0.001)
                    zeroCurvatureCount++;
            }
            if (zeroCurvatureCount > this.moveEvents.length - 2) {
                triggered = true;
                actualVal = `Linear robotic trajectory detected: ${zeroCurvatureCount}/${this.moveEvents.length} points collinear`;
            }
        }
        evidence["actual_value"] = actualVal;
        if (!triggered) {
            evidence["remediation_guidance"] = "No action required. Mouse movement kinematics verified.";
        }
        return {
            id: "mouse_movement_analysis_detector",
            triggered,
            severity: triggered ? 3 : 0,
            category: "bot_intelligence",
            event: triggered ? "bot_mouse_trajectory_detected" : "human_mouse_verified",
            evidence
        };
    }
}
