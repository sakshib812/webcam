/**
 * SecureClipboard: Timed Auto-Wipe & Sensitive Input Exfiltration Shield
 *
 * Web equivalent of Android KeyStore clipboard data scrubbing.
 * Allows applications to place sensitive data (OTP codes, private keys, credit cards)
 * on the system clipboard with an automated time-to-live (TTL) auto-wipe timer.
 */
export class SecureClipboard {
    static activeWipeTimer = null;
    static lastCopiedSensitiveHash = null;
    /**
     * Writes sensitive text to the clipboard and starts an automatic wipe countdown timer.
     */
    static async copy(text, wipeAfterMs = 30000) {
        let success = false;
        // 1. Attempt Modern Web Clipboard API
        if (typeof navigator !== 'undefined' && navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
            try {
                await navigator.clipboard.writeText(text);
                success = true;
            }
            catch (err) {
                console.warn('[SecureShield] navigator.clipboard write failed, attempting fallback:', err.message);
            }
        }
        // 2. Fallback to execCommand if Modern API failed or blocked
        if (!success && typeof document !== 'undefined' && typeof document.createElement === 'function') {
            try {
                const textarea = document.createElement('textarea');
                textarea.value = text;
                textarea.style.position = 'fixed';
                textarea.style.left = '-999999px';
                textarea.style.top = '-999999px';
                if (document.body) {
                    document.body.appendChild(textarea);
                    textarea.focus();
                    textarea.select();
                    success = document.execCommand('copy');
                    document.body.removeChild(textarea);
                }
            }
            catch (fbErr) {
                console.warn('[SecureShield] execCommand fallback failed:', fbErr.message);
            }
        }
        // If in Node/test environment with mock
        if (!success && globalThis.__mockClipboard) {
            globalThis.__mockClipboard = text;
            success = true;
        }
        // Clear any previous pending wipe timer
        SecureClipboard.cancelActiveWipe();
        const cancelFn = () => {
            SecureClipboard.cancelActiveWipe();
        };
        if (success && wipeAfterMs > 0) {
            SecureClipboard.activeWipeTimer = setTimeout(async () => {
                await SecureClipboard.wipeNow();
            }, wipeAfterMs);
        }
        return {
            success,
            wipeAfterMs,
            cancelWipe: cancelFn
        };
    }
    /**
     * Immediately clears/overwrites the system clipboard.
     */
    static async wipeNow() {
        SecureClipboard.cancelActiveWipe();
        if (typeof navigator !== 'undefined' && navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
            try {
                await navigator.clipboard.writeText('');
                return true;
            }
            catch {
                // Fallback
            }
        }
        if (globalThis.__mockClipboard !== undefined) {
            globalThis.__mockClipboard = '';
            return true;
        }
        return false;
    }
    /**
     * Cancels any pending auto-wipe countdown timer.
     */
    static cancelActiveWipe() {
        if (SecureClipboard.activeWipeTimer) {
            clearTimeout(SecureClipboard.activeWipeTimer);
            SecureClipboard.activeWipeTimer = null;
        }
    }
    /**
     * Hardens designated sensitive input elements against unauthorized cut/copy/drag exfiltration.
     */
    static protectSensitiveInputs(selector = 'input[type="password"], [data-secureshield-protected], input[autocomplete="cc-number"]') {
        if (typeof document === 'undefined' || typeof document.querySelectorAll !== 'function') {
            return;
        }
        try {
            const inputs = document.querySelectorAll(selector);
            inputs.forEach((el) => {
                const preventExfil = (e) => {
                    e.preventDefault();
                    console.warn('[SecureShield] Blocked clipboard exfiltration attempt on protected input field.');
                };
                el.addEventListener('copy', preventExfil);
                el.addEventListener('cut', preventExfil);
                el.addEventListener('dragstart', preventExfil);
            });
        }
        catch {
            // Ignore query error
        }
    }
}
