import { DetectorItem } from '../telemetry.js';
/**
 * ClipboardHijackingDetector: P4 Informational / Extension Security Detector.
 *
 * Audits `navigator.clipboard.writeText` and `document.execCommand` for unauthorized
 * monkey-patching and detects rogue `copy`/`cut` event listeners replacing clipboard content.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.02ms (Clipboard API descriptor and native inspection)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: Never reads user clipboard data directly
 * - Evasion Limits: Native OS-level keyloggers/clipboard managers cannot be observed via Web APIs.
 */
export declare class ClipboardHijackingDetector {
    static scan(): DetectorItem;
}
