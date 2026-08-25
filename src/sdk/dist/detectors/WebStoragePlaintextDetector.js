export class WebStoragePlaintextDetector {
    static scan() {
        let triggered = false;
        const evidence = {};
        const sensitiveRegex = /(api_key|token|auth|password|jwt|secret|access_token)/i;
        try {
            // Check localStorage
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                if (key && sensitiveRegex.test(key)) {
                    const val = localStorage.getItem(key) || '';
                    if (!val.startsWith('ey') && val.length > 5) { // Unencrypted token
                        triggered = true;
                        evidence['local_storage_key'] = key;
                        break;
                    }
                }
            }
            // Check sessionStorage
            for (let i = 0; i < sessionStorage.length; i++) {
                const key = sessionStorage.key(i);
                if (key && sensitiveRegex.test(key)) {
                    const val = sessionStorage.getItem(key) || '';
                    if (!val.startsWith('ey') && val.length > 5) {
                        triggered = true;
                        evidence['session_storage_key'] = key;
                        break;
                    }
                }
            }
        }
        catch (e) {
            evidence['error'] = e.message;
        }
        return {
            id: 'web_storage_plaintext_detector',
            triggered,
            severity: 2, // MEDIUM
            category: 'app',
            event: 'unencrypted_web_storage_secret_detected',
            evidence
        };
    }
}
