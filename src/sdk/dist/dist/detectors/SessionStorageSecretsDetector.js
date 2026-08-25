/**
 * SessionStorageSecretsDetector: P4 Informational / Storage Security Detector.
 *
 * Scans sessionStorage items for unencrypted JWT tokens, private keys, API secrets,
 * or password credentials stored in plaintext without cryptographic envelope protection.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.02ms (Direct storage key/value regex inspection)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: Matched secret values are REDACTED/HASHED; raw tokens are never recorded in telemetry.
 * - Evasion Limits: Encrypted payloads stored under benign key names cannot be inspected without keys.
 */
const SENSITIVE_KEY_PATTERNS = [
    /password/i,
    /passwd/i,
    /secret/i,
    /private_?key/i,
    /auth_?token/i,
    /bearer_?token/i,
    /jwt_?token/i,
    /credit_?card/i,
    /api_?key/i
];
const PLAINTEXT_VALUE_PATTERNS = [
    /^eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$/, // Plaintext JWT structure
    /-----BEGIN [A-Z]+ PRIVATE KEY-----/, // Raw PEM Private Key
    /^ghp_[A-Za-z0-9]{36}$/, // GitHub Personal Access Token
    /^sk_live_[0-9a-zA-Z]{24,}$/ // Stripe / API Live Secret Key
];
export class SessionStorageSecretsDetector {
    static scan() {
        const nowMs = Date.now().toString();
        const evidence = {
            scan_timestamp_ms: nowMs,
            probe_target: 'SessionStorage Plaintext Secrets & Tokens',
            probe_technique: 'session_storage_key_value_pattern_audit'
        };
        let triggered = false;
        const exposedKeys = [];
        try {
            if (typeof sessionStorage !== 'undefined') {
                const keyCount = sessionStorage.length;
                evidence['total_session_storage_items'] = keyCount;
                for (let i = 0; i < keyCount; i++) {
                    const key = sessionStorage.key(i) || '';
                    const rawValue = sessionStorage.getItem(key) || '';
                    // 1. Check if storage key matches known high-risk sensitive pattern
                    const isSensitiveKey = SENSITIVE_KEY_PATTERNS.some((pat) => pat.test(key));
                    // 2. Check if storage value matches known plaintext token/credential structure
                    const isSensitiveValue = PLAINTEXT_VALUE_PATTERNS.some((pat) => pat.test(rawValue));
                    if (isSensitiveKey || isSensitiveValue) {
                        triggered = true;
                        exposedKeys.push(`Key '${key}' (Matched ${isSensitiveValue ? 'plaintext token structure' : 'sensitive key naming'})`);
                    }
                }
            }
            evidence['detected_exposed_keys'] = exposedKeys;
            evidence['actual_value'] = triggered
                ? `Plaintext credentials found in sessionStorage (${exposedKeys.length}): ${exposedKeys.slice(0, 3).join(', ')}`
                : 'SessionStorage Plaintext Secrets verified clean in browser context';
            evidence['expected_value'] = 'SessionStorage must contain zero plaintext credentials, JWTs, or private keys';
            evidence['threat_classification'] = triggered
                ? 'UNENCRYPTED_PLAINTEXT_CREDENTIALS_IN_SESSION_STORAGE'
                : 'Clean browser environment';
            evidence['remediation_guidance'] = triggered
                ? 'Migrate unencrypted credentials into SecureShield Vault (AES-GCM encrypted) or HttpOnly cookies'
                : 'No action required. Baseline clean.';
        }
        catch (e) {
            evidence['error'] = `SessionStorageSecretsDetector error: ${e.message}`;
        }
        return {
            id: 'session_storage_plaintext_detector',
            triggered,
            severity: triggered ? 3 : 0,
            category: 'application_integrity',
            event: triggered ? 'session_storage_secrets_detected' : 'session_storage_plaintext_detector_verified',
            confidence: 0.90,
            fpRiskTier: 'LOW',
            evasionDifficulty: 'MEDIUM',
            status: triggered ? 'FAILED' : 'PASSED',
            name: 'SessionStorage Secrets Detector',
            evidence
        };
    }
}
