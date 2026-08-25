/**
 * RemediationManager: Over-The-Air Threat Remediation & Action Dispatcher
 *
 * Implements automated client-side remediation for server decision actions:
 * - PAUSED: Dynamically suspends SDK probes and background listeners.
 * - WIPE_LOCAL_KEYS: Purges non-exportable IndexedDB vault, session tokens, and cached credentials.
 * - TERMINATE_APP / BLOCK_DEVICE: Performs complete lockdown (vault wipe + DOM lockout overlay + URL redirect).
 */
import { IndexedDbLeaseVault } from '../storage/IndexedDbLeaseVault.js';
import { SecurityLockoutOverlay } from '../ui/SecurityLockoutOverlay.js';
export class RemediationManager {
    options;
    constructor(options) {
        this.options = {
            blockRedirectUrl: options?.blockRedirectUrl !== undefined ? options.blockRedirectUrl : '/access-blocked',
            enableDomLockoutOverlay: options?.enableDomLockoutOverlay ?? true,
            onRemediationTriggered: options?.onRemediationTriggered,
            onWipeKeys: options?.onWipeKeys
        };
    }
    /**
     * Purges all non-exportable IndexedDB keys, session storage, and cached auth credentials.
     */
    async wipeLocalKeys() {
        try {
            // 1. Purge non-exportable IndexedDB session lease vault
            await IndexedDbLeaseVault.clearVault();
        }
        catch (e) {
            console.warn('[SecureShield] Error purging IndexedDB vault:', e.message);
        }
        try {
            // 2. Clear volatile session storage
            if (typeof sessionStorage !== 'undefined') {
                sessionStorage.clear();
            }
        }
        catch (e) {
            console.warn('[SecureShield] Error clearing sessionStorage:', e.message);
        }
        try {
            // 3. Purge sensitive credentials from localStorage
            if (typeof localStorage !== 'undefined') {
                const keysToRemove = [];
                for (let i = 0; i < localStorage.length; i++) {
                    const k = localStorage.key(i);
                    if (k && (k.startsWith('secureshield_') ||
                        k.startsWith('auth_') ||
                        k.startsWith('jwt') ||
                        k.includes('token') ||
                        k.startsWith('session_'))) {
                        keysToRemove.push(k);
                    }
                }
                for (const k of keysToRemove) {
                    localStorage.removeItem(k);
                }
            }
        }
        catch (e) {
            console.warn('[SecureShield] Error clearing localStorage credentials:', e.message);
        }
        try {
            // 4. Trigger consumer callback if supplied
            this.options.onWipeKeys?.();
        }
        catch (e) {
            console.warn('[SecureShield] Error in onWipeKeys callback:', e.message);
        }
    }
    /**
     * Processes a server-returned decision action and applies immediate client remediation.
     */
    async handleDecisionAction(rawAction, reason) {
        if (!rawAction || typeof rawAction !== 'string') {
            return { action: 'NONE', enforced: false };
        }
        const action = rawAction.toUpperCase().trim();
        // 1. PAUSED Action
        if (action === 'PAUSED') {
            console.warn('[SecureShield] OVER-THE-AIR POLICY: SDK Enforcement and Probes have been PAUSED by System Admin.');
            this.options.onRemediationTriggered?.('PAUSED', reason || 'SDK Paused by Admin Policy');
            return {
                action: 'PAUSED',
                enforced: true,
                details: 'SDK probe execution suspended by Admin'
            };
        }
        // 2. WIPE_LOCAL_KEYS Action
        if (action === 'WIPE_LOCAL_KEYS') {
            console.warn('[SecureShield] CRITICAL REMEDIATION: Wiping local cryptographic keys and cached session tokens.');
            await this.wipeLocalKeys();
            this.options.onRemediationTriggered?.('WIPE_LOCAL_KEYS', reason || 'Threat detected: local keys wiped');
            return {
                action: 'WIPE_LOCAL_KEYS',
                enforced: true,
                details: 'IndexedDB vault and session storage credentials wiped'
            };
        }
        // 3. TERMINATE_APP / BLOCK_DEVICE / BLOCK_ACTION
        if (action === 'TERMINATE_APP' || action === 'BLOCK_DEVICE' || action === 'BLOCK_ACTION') {
            console.error(`[SecureShield CRITICAL] THREAT REMEDIATION TRIGGERED (${action}). Terminating application session.`);
            // Step A: Wipe local keys & revoke sessions
            await this.wipeLocalKeys();
            // Step B: Trigger consumer notification
            this.options.onRemediationTriggered?.(action, reason || `Critical threat detected: ${action}`);
            // Step C: Render DOM Lockout Shield
            if (this.options.enableDomLockoutOverlay !== false) {
                SecurityLockoutOverlay.renderLockoutOverlay('🚨 Access Blocked: Security Violation', reason || 'Your application session has been terminated by enterprise policy due to a security violation.');
            }
            // Step D: Perform URL Redirection if configured
            if (this.options.blockRedirectUrl && typeof window !== 'undefined' && window.location) {
                try {
                    if (typeof window.location.replace === 'function') {
                        window.location.replace(this.options.blockRedirectUrl);
                    }
                    else {
                        window.location.href = this.options.blockRedirectUrl;
                    }
                }
                catch {
                    // Ignore redirect error
                }
            }
            return {
                action,
                enforced: true,
                details: `App session terminated and blocked (${action})`
            };
        }
        return {
            action,
            enforced: false,
            details: 'Normal execution continued'
        };
    }
}
