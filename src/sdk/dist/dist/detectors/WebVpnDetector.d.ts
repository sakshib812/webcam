import { DetectorItem } from '../telemetry.js';
/**
 * WebVpnDetector: P4 Informational / Network Security Detector.
 *
 * Audits WebRTC RTCPeerConnection interfaces and compares timezone offset consistency
 * against navigator languages and locales to detect VPN tunneling and proxy routing nodes.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.02ms (Timezone and WebRTC interface inspection)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: None exfiltrated
 * - Evasion Limits: Commercial VPNs that spoof both system timezone and WebRTC routes
 *   require IP-based threat intelligence matching on the backend.
 */
export declare class WebVpnDetector {
    static scan(): DetectorItem;
}
