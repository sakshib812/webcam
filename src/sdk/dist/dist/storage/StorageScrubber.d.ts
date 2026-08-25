/**
 * StorageScrubber: Browser Storage Audit & Sensitive Plaintext Sanitizer
 *
 * Scans localStorage and sessionStorage for unencrypted credentials, exposed JWTs,
 * API tokens, and session secrets. Purges unsafe storage leaks while preserving
 * standard application preferences.
 */
export interface StorageLeakItem {
    storage: 'localStorage' | 'sessionStorage';
    key: string;
    reason: string;
}
export interface StorageLeakReport {
    leaksFound: number;
    leakingKeys: StorageLeakItem[];
    inspectedCount: number;
}
export declare class StorageScrubber {
    private static SENSITIVE_KEY_PATTERNS;
    private static SENSITIVE_VALUE_PATTERNS;
    /**
     * Performs an audit sweep of browser storage to identify exposed plaintext secrets.
     */
    static scanForPlaintextLeaks(): StorageLeakReport;
    /**
     * Selectively purges identified plaintext credential leaks while preserving safe application settings.
     */
    static purgePlaintextLeaks(whitelistKeys?: string[]): StorageLeakReport;
    /**
     * Completely clears volatile sessionStorage and non-essential caches.
     */
    static wipeVolatileStorage(): void;
    /**
     * Evaluates if a given storage key-value pair constitutes a credential exposure risk.
     */
    private static evaluatePotentialLeak;
}
