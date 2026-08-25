/**
 * IndexedDbLeaseVault: Non-Exportable Cryptographic Vault & Offline Session Lease Manager
 *
 * Implements hardware-adjacent browser key storage using standard IndexedDB + Web Crypto API.
 * The master encryption key is generated with extractable=false (non-exportable), meaning raw key bytes
 * never enter userland JavaScript memory and cannot be exfiltrated via devtools or script injection.
 *
 * Provides offline session grace lease caching mirroring Android KeyStore / EncryptedSharedPreferences.
 */
import { MemoryScrubber } from '../crypto/MemoryScrubber.js';
export class IndexedDbLeaseVault {
    static DB_NAME = 'secureshield_auth_vault';
    static DB_VERSION = 1;
    static STORE_KEYS = 'master_keys';
    static STORE_LEASES = 'leases';
    static MASTER_KEY_ID = 'lease_master_key';
    static LEASE_RECORD_ID = 'cached_session_lease';
    // In-memory fallback stores for headless / private-browsing / test environments
    static memoryKeyStore = new Map();
    static memoryLeaseStore = new Map();
    /**
     * Helper: Resolves standard Web Crypto instance
     */
    static getSubtleCrypto() {
        if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle) {
            return globalThis.crypto.subtle;
        }
        if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
            return window.crypto.subtle;
        }
        throw new Error('Web Crypto API (crypto.subtle) is not available.');
    }
    /**
     * Helper: Checks if native browser IndexedDB is accessible
     */
    static isIndexedDbAvailable() {
        try {
            return typeof globalThis !== 'undefined' && typeof globalThis.indexedDB !== 'undefined';
        }
        catch {
            return false;
        }
    }
    /**
     * Opens or initializes the IndexedDB database instance
     */
    static openDatabase() {
        return new Promise((resolve, reject) => {
            if (!IndexedDbLeaseVault.isIndexedDbAvailable()) {
                return reject(new Error('IndexedDB is not supported in the current environment.'));
            }
            const idb = globalThis.indexedDB;
            const request = idb.open(IndexedDbLeaseVault.DB_NAME, IndexedDbLeaseVault.DB_VERSION);
            request.onupgradeneeded = (event) => {
                const db = event.target.result;
                if (!db.objectStoreNames.contains(IndexedDbLeaseVault.STORE_KEYS)) {
                    db.createObjectStore(IndexedDbLeaseVault.STORE_KEYS);
                }
                if (!db.objectStoreNames.contains(IndexedDbLeaseVault.STORE_LEASES)) {
                    db.createObjectStore(IndexedDbLeaseVault.STORE_LEASES, { keyPath: 'id' });
                }
            };
            request.onsuccess = (event) => {
                resolve(event.target.result);
            };
            request.onerror = (event) => {
                reject(event.target.error || new Error('Failed to open IndexedDB vault'));
            };
        });
    }
    /**
     * Retrieves existing non-exportable CryptoKey or generates a new one.
     * Key is generated with extractable=false so raw bytes cannot be exported.
     */
    static async getOrCreateMasterKey() {
        const subtle = IndexedDbLeaseVault.getSubtleCrypto();
        // 1. Attempt retrieval from IndexedDB
        if (IndexedDbLeaseVault.isIndexedDbAvailable()) {
            try {
                const db = await IndexedDbLeaseVault.openDatabase();
                const existingKey = await new Promise((resolve, reject) => {
                    try {
                        const tx = db.transaction(IndexedDbLeaseVault.STORE_KEYS, 'readonly');
                        const store = tx.objectStore(IndexedDbLeaseVault.STORE_KEYS);
                        const req = store.get(IndexedDbLeaseVault.MASTER_KEY_ID);
                        req.onsuccess = () => resolve(req.result || null);
                        req.onerror = () => reject(req.error);
                    }
                    catch (e) {
                        reject(e);
                    }
                });
                if (existingKey) {
                    return existingKey;
                }
                // Generate fresh non-exportable AES-GCM 256-bit key
                const newKey = await subtle.generateKey({
                    name: 'AES-GCM',
                    length: 256
                }, false, // extractable = false (NON-EXPORTABLE!)
                ['encrypt', 'decrypt']);
                // Store non-exportable key object via Structured Clone
                await new Promise((resolve, reject) => {
                    try {
                        const tx = db.transaction(IndexedDbLeaseVault.STORE_KEYS, 'readwrite');
                        const store = tx.objectStore(IndexedDbLeaseVault.STORE_KEYS);
                        const req = store.put(newKey, IndexedDbLeaseVault.MASTER_KEY_ID);
                        req.onsuccess = () => resolve();
                        req.onerror = () => reject(req.error);
                    }
                    catch (e) {
                        reject(e);
                    }
                });
                return newKey;
            }
            catch (idbErr) {
                // Fallback to memory key if IndexedDB transaction failed
            }
        }
        // 2. Memory fallback for test / restricted contexts
        let memKey = IndexedDbLeaseVault.memoryKeyStore.get(IndexedDbLeaseVault.MASTER_KEY_ID);
        if (!memKey) {
            memKey = await subtle.generateKey({
                name: 'AES-GCM',
                length: 256
            }, false, // extractable = false
            ['encrypt', 'decrypt']);
            IndexedDbLeaseVault.memoryKeyStore.set(IndexedDbLeaseVault.MASTER_KEY_ID, memKey);
        }
        return memKey;
    }
    /**
     * Encrypts and persists a verified session lease in the vault.
     */
    static async saveLease(payload) {
        const subtle = IndexedDbLeaseVault.getSubtleCrypto();
        const masterKey = await IndexedDbLeaseVault.getOrCreateMasterKey();
        const iv = new Uint8Array(12);
        if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
            crypto.getRandomValues(iv);
        }
        else {
            for (let i = 0; i < 12; i++)
                iv[i] = Math.floor(Math.random() * 256);
        }
        const encoder = new TextEncoder();
        const jsonBytes = encoder.encode(JSON.stringify(payload));
        const ciphertextBuffer = await subtle.encrypt({
            name: 'AES-GCM',
            iv: iv,
            tagLength: 128
        }, masterKey, jsonBytes);
        // Scrub plaintext buffer immediately after encryption
        MemoryScrubber.zero(jsonBytes);
        // Encode IV & Ciphertext for storage
        const ivB64 = IndexedDbLeaseVault.bytesToBase64(iv);
        const ciphertextB64 = IndexedDbLeaseVault.bytesToBase64(new Uint8Array(ciphertextBuffer));
        MemoryScrubber.zero(iv);
        const record = {
            id: IndexedDbLeaseVault.LEASE_RECORD_ID,
            iv: ivB64,
            ciphertext: ciphertextB64,
            timestamp: Date.now()
        };
        if (IndexedDbLeaseVault.isIndexedDbAvailable()) {
            try {
                const db = await IndexedDbLeaseVault.openDatabase();
                await new Promise((resolve, reject) => {
                    const tx = db.transaction(IndexedDbLeaseVault.STORE_LEASES, 'readwrite');
                    const store = tx.objectStore(IndexedDbLeaseVault.STORE_LEASES);
                    const req = store.put(record);
                    req.onsuccess = () => resolve();
                    req.onerror = () => reject(req.error);
                });
                return;
            }
            catch {
                // Fallback to memory
            }
        }
        IndexedDbLeaseVault.memoryLeaseStore.set(IndexedDbLeaseVault.LEASE_RECORD_ID, record);
    }
    /**
     * Decrypts and retrieves the cached session lease from the vault.
     */
    static async getLease() {
        const subtle = IndexedDbLeaseVault.getSubtleCrypto();
        let record = null;
        if (IndexedDbLeaseVault.isIndexedDbAvailable()) {
            try {
                const db = await IndexedDbLeaseVault.openDatabase();
                record = await new Promise((resolve, reject) => {
                    const tx = db.transaction(IndexedDbLeaseVault.STORE_LEASES, 'readonly');
                    const store = tx.objectStore(IndexedDbLeaseVault.STORE_LEASES);
                    const req = store.get(IndexedDbLeaseVault.LEASE_RECORD_ID);
                    req.onsuccess = () => resolve(req.result || null);
                    req.onerror = () => reject(req.error);
                });
            }
            catch {
                // Fallback to memory
            }
        }
        if (!record) {
            record = IndexedDbLeaseVault.memoryLeaseStore.get(IndexedDbLeaseVault.LEASE_RECORD_ID) || null;
        }
        if (!record || !record.ciphertext || !record.iv) {
            return null;
        }
        try {
            const masterKey = await IndexedDbLeaseVault.getOrCreateMasterKey();
            const iv = IndexedDbLeaseVault.base64ToBytes(record.iv);
            const ciphertext = IndexedDbLeaseVault.base64ToBytes(record.ciphertext);
            const decryptedBuffer = await subtle.decrypt({
                name: 'AES-GCM',
                iv: iv,
                tagLength: 128
            }, masterKey, ciphertext);
            MemoryScrubber.zero(iv);
            MemoryScrubber.zero(ciphertext);
            const decoder = new TextDecoder();
            const jsonStr = decoder.decode(decryptedBuffer);
            return JSON.parse(jsonStr);
        }
        catch (decErr) {
            return null;
        }
    }
    /**
     * Verifies if an active, non-expired offline grace lease exists for the current appId and origin.
     */
    static async verifyOfflineLease(appId, currentOrigin) {
        const lease = await IndexedDbLeaseVault.getLease();
        if (!lease) {
            return {
                isValid: false,
                reason: 'No cached encrypted session lease found in vault.'
            };
        }
        const now = Date.now();
        if (now >= lease.leaseExpiryMs) {
            return {
                isValid: false,
                reason: `Cached session lease has expired (Expired at: ${new Date(lease.leaseExpiryMs).toISOString()}).`
            };
        }
        if (lease.appId !== appId) {
            return {
                isValid: false,
                reason: `AppId mismatch: Lease registered for '${lease.appId}', current is '${appId}'.`
            };
        }
        // Origin verification
        const cleanLeaseOrigin = lease.origin.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase();
        const cleanCurrentOrigin = currentOrigin.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase();
        if (cleanLeaseOrigin && cleanCurrentOrigin && !cleanCurrentOrigin.includes(cleanLeaseOrigin)) {
            return {
                isValid: false,
                reason: `Origin mismatch: Lease bound to '${lease.origin}', current is '${currentOrigin}'.`
            };
        }
        return {
            isValid: true,
            lease
        };
    }
    /**
     * Completely clears all keys and leases from the vault (used during remote threat remediation / WIPE_LOCAL_KEYS).
     */
    static async clearVault() {
        IndexedDbLeaseVault.memoryKeyStore.clear();
        IndexedDbLeaseVault.memoryLeaseStore.clear();
        if (IndexedDbLeaseVault.isIndexedDbAvailable()) {
            try {
                const db = await IndexedDbLeaseVault.openDatabase();
                await new Promise((resolve, reject) => {
                    const tx = db.transaction([IndexedDbLeaseVault.STORE_KEYS, IndexedDbLeaseVault.STORE_LEASES], 'readwrite');
                    tx.objectStore(IndexedDbLeaseVault.STORE_KEYS).clear();
                    tx.objectStore(IndexedDbLeaseVault.STORE_LEASES).clear();
                    tx.oncomplete = () => resolve();
                    tx.onerror = () => reject(tx.error);
                });
            }
            catch {
                // Fallback
            }
        }
    }
    /**
     * Universal Base64 Helpers
     */
    static bytesToBase64(bytes) {
        let binary = '';
        for (let i = 0; i < bytes.length; i++)
            binary += String.fromCharCode(bytes[i]);
        if (typeof btoa === 'function')
            return btoa(binary);
        const nodeBuf = globalThis.Buffer;
        if (typeof nodeBuf !== 'undefined')
            return nodeBuf.from(bytes).toString('base64');
        throw new Error('Base64 encoding not supported.');
    }
    static base64ToBytes(base64) {
        const cleanB64 = base64.replace(/[\r\n\s]/g, '');
        if (typeof atob === 'function') {
            const binary = atob(cleanB64);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++)
                bytes[i] = binary.charCodeAt(i);
            return bytes;
        }
        const nodeBuf = globalThis.Buffer;
        if (typeof nodeBuf !== 'undefined')
            return new Uint8Array(nodeBuf.from(cleanB64, 'base64'));
        throw new Error('Base64 decoding not supported.');
    }
}
