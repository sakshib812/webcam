import { DetectorItem } from '../telemetry.js';
/**
 * ExtensionInjectionDetector: P4 Informational / Extension Security Detector.
 *
 * Scans DOM `<head>` and `<body>` elements for `<script>`, `<link>`, or `<iframe>` tags
 * loaded directly from browser extension protocol schemes (`chrome-extension://`, `moz-extension://`).
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.03ms (DOM protocol scheme query)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: None read or exfiltrated
 * - Evasion Limits: Extensions using pure programmatic message passing without
 *   inserting DOM elements cannot be detected via DOM sweeping.
 */
export declare class ExtensionInjectionDetector {
    static scan(): DetectorItem;
}
