/**
 * RemediationManager: Over-The-Air Threat Remediation & Action Dispatcher
 *
 * Implements automated client-side remediation for server decision actions:
 * - PAUSED: Dynamically suspends SDK probes and background listeners.
 * - WIPE_LOCAL_KEYS: Purges non-exportable IndexedDB vault, session tokens, and cached credentials.
 * - TERMINATE_APP / BLOCK_DEVICE: Performs complete lockdown (vault wipe + DOM lockout overlay + URL redirect).
 */
export interface RemediationOptions {
    blockRedirectUrl?: string | null;
    enableDomLockoutOverlay?: boolean;
    onRemediationTriggered?: (action: string, reason?: string) => void;
    onWipeKeys?: () => void;
}
export interface RemediationResult {
    action: string;
    enforced: boolean;
    details?: string;
}
export declare class RemediationManager {
    private options;
    constructor(options?: RemediationOptions);
    /**
     * Purges all non-exportable IndexedDB keys, session storage, and cached auth credentials.
     */
    wipeLocalKeys(): Promise<void>;
    /**
     * Processes a server-returned decision action and applies immediate client remediation.
     */
    handleDecisionAction(rawAction?: string, reason?: string): Promise<RemediationResult>;
}
