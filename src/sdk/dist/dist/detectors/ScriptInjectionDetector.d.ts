import { DetectorItem } from '../telemetry.js';
/**
 * ScriptInjectionDetector: P0 Critical Regulatory Baseline Detector.
 *
 * Scans the DOM for unauthorized script tags, inline scripts with encoded/eval payloads,
 * unapproved external script origins, and DOM-based XSS injection artifacts.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.05ms for typical DOM (<100 script tags); MutationObserver uses microtask batching
 * - Execution Model: On-demand synchronous DOM sweep + optional continuous MutationObserver
 * - Sensitive Data: Matched suspicious payload strings are hashed/redacted before reporting
 * - Evasion Limits: Highly sophisticated XSS attacks using multi-stage WebSocket payloads
 *   or pure DOM property manipulation without eval/atob signatures may evade static pattern matching.
 *   This detector serves as defense-in-depth alongside strict Content-Security-Policy (CSP) headers.
 */
export interface ScriptInjectionOptions {
    allowedScriptOrigins?: string[];
    blockInlineEvalPatterns?: boolean;
}
export declare class ScriptInjectionDetector {
    private static defaultAllowedOrigins;
    /**
     * Configures global allowed script origins
     */
    static setAllowedOrigins(origins: string[]): void;
    /**
     * Initializes a background MutationObserver on document to catch runtime script injections
     */
    static initObserver(options?: ScriptInjectionOptions): void;
    /**
     * Analyzes an individual script source & content for suspicious patterns
     */
    static analyzeScript(src: string, content: string, allowedOrigins?: string[]): {
        flagged: boolean;
        reason: string;
        severity: number;
    };
    static scan(options?: ScriptInjectionOptions): DetectorItem;
    /**
     * Resets recorded mutation observer injections (useful for test isolations)
     */
    static clearObservedMutations(): void;
}
