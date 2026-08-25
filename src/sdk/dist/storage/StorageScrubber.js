/**
 * StorageScrubber: Browser Storage Audit & Sensitive Plaintext Sanitizer
 *
 * Scans localStorage and sessionStorage for unencrypted credentials, exposed JWTs,
 * API tokens, and session secrets. Purges unsafe storage leaks while preserving
 * standard application preferences.
 */
export class StorageScrubber {
    static SENSITIVE_KEY_PATTERNS = [
        /jwt/i,
        /token/i,
        /auth/i,
        /secret/i,
        /api[_-]?key/i,
        /private[_-]?key/i,
        /bearer/i,
        /password/i,
        /credential/i,
        /session[_-]?id/i,
        /oauth/i
    ];
    static SENSITIVE_VALUE_PATTERNS = [
        /^eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$/, // JWT Token format
        /^Bearer\s+[A-Za-z0-9-_=]+/i, // Bearer Authorization
        /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/, // Private Key PEM
        /^[A-Fa-f0-9]{64}$/ // 256-bit Raw Hex Secret
    ];
    /**
     * Performs an audit sweep of browser storage to identify exposed plaintext secrets.
     */
    static scanForPlaintextLeaks() {
        const leakingKeys = [];
        let inspectedCount = 0;
        // 1. Audit localStorage
        if (typeof localStorage !== 'undefined') {
            try {
                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i);
                    if (!key)
                        continue;
                    inspectedCount++;
                    const val = localStorage.getItem(key) || '';
                    const leakReason = StorageScrubber.evaluatePotentialLeak(key, val);
                    if (leakReason) {
                        leakingKeys.push({ storage: 'localStorage', key, reason: leakReason });
                    }
                }
            }
            catch {
                // Handle storage access error (e.g. cookies disabled)
            }
        }
        // 2. Audit sessionStorage
        if (typeof sessionStorage !== 'undefined') {
            try {
                for (let i = 0; i < sessionStorage.length; i++) {
                    const key = sessionStorage.key(i);
                    if (!key)
                        continue;
                    inspectedCount++;
                    const val = sessionStorage.getItem(key) || '';
                    const leakReason = StorageScrubber.evaluatePotentialLeak(key, val);
                    if (leakReason) {
                        leakingKeys.push({ storage: 'sessionStorage', key, reason: leakReason });
                    }
                }
            }
            catch {
                // Handle storage access error
            }
        }
        return {
            leaksFound: leakingKeys.length,
            leakingKeys,
            inspectedCount
        };
    }
    /**
     * Selectively purges identified plaintext credential leaks while preserving safe application settings.
     */
    static purgePlaintextLeaks(whitelistKeys = []) {
        const report = StorageScrubber.scanForPlaintextLeaks();
        const whitelistSet = new Set(whitelistKeys.map(k => k.toLowerCase()));
        for (const item of report.leakingKeys) {
            if (whitelistSet.has(item.key.toLowerCase())) {
                continue; // Preserved via explicit consumer whitelist
            }
            try {
                if (item.storage === 'localStorage' && typeof localStorage !== 'undefined') {
                    localStorage.removeItem(item.key);
                    console.warn(`[SecureShield] StorageScrubber purged unencrypted secret from localStorage: '${item.key}' (${item.reason})`);
                }
                else if (item.storage === 'sessionStorage' && typeof sessionStorage !== 'undefined') {
                    sessionStorage.removeItem(item.key);
                    console.warn(`[SecureShield] StorageScrubber purged unencrypted secret from sessionStorage: '${item.key}' (${item.reason})`);
                }
            }
            catch {
                // Ignore deletion error
            }
        }
        return report;
    }
    /**
     * Completely clears volatile sessionStorage and non-essential caches.
     */
    static wipeVolatileStorage() {
        if (typeof sessionStorage !== 'undefined') {
            try {
                sessionStorage.clear();
            }
            catch {
                // Ignore
            }
        }
    }
    /**
     * Evaluates if a given storage key-value pair constitutes a credential exposure risk.
     */
    static evaluatePotentialLeak(key, value) {
        // Whitelist internal SecureShield encrypted identifiers (which are safe ciphertext hashes)
        if (key === 'secureshield_auth_vault' || key.startsWith('secureshield_encrypted_')) {
            return null;
        }
        // Check value format
        for (const pattern of StorageScrubber.SENSITIVE_VALUE_PATTERNS) {
            if (pattern.test(value.trim())) {
                return 'Plaintext JWT, token, or private key structure detected in storage value';
            }
        }
        // Check key naming
        for (const pattern of StorageScrubber.SENSITIVE_KEY_PATTERNS) {
            if (pattern.test(key)) {
                return `Storage key name '${key}' matches known sensitive credential pattern`;
            }
        }
        return null;
    }
}
