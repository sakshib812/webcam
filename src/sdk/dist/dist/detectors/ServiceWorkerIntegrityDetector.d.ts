import { DetectorItem } from '../telemetry.js';
/**
 * ServiceWorkerIntegrityDetector: P4 Informational / Application Integrity Detector.
 *
 * Audits `navigator.serviceWorker.register` and active Service Worker registrations
 * to identify rogue service workers registered from unapproved scopes or external scripts.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.02ms (Registration API descriptor and scope inspection)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: None read or recorded
 * - Evasion Limits: Service Workers already registered on different subpaths before
 *   the page load require asynchronous `navigator.serviceWorker.getRegistrations()` audit.
 */
export declare class ServiceWorkerIntegrityDetector {
    static scan(): DetectorItem;
}
