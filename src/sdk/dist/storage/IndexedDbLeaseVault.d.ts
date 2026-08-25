/**
 * IndexedDbLeaseVault: Non-Exportable Cryptographic Vault & Offline Session Lease Manager
 *
 * Implements hardware-adjacent browser key storage using standard IndexedDB + Web Crypto API.
 * The master encryption key is generated with extractable=false (non-exportable), meaning raw key bytes
 * never enter userland JavaScript memory and cannot be exfiltrated via devtools or script injection.
 *
 * Provides offline session grace lease caching mirroring Android KeyStore / EncryptedSharedPreferences.
 */
export interface CachedLeasePayload {
    appId: string;
    tenantId: string;
    origin: string;
    policy: any;
    leaseExpiryMs: number;
    cachedAt: number;
}
export interface EncryptedLeaseRecord {
    id: string;
    iv: string;
    ciphertext: string;
    timestamp: number;
}
export interface LeaseVerificationResult {
    isValid: boolean;
    lease?: CachedLeasePayload;
    reason?: string;
}
export declare class IndexedDbLeaseVault {
    static DB_NAME: string;
    static DB_VERSION: number;
    static STORE_KEYS: string;
    static STORE_LEASES: string;
    static MASTER_KEY_ID: string;
    static LEASE_RECORD_ID: string;
    private static memoryKeyStore;
    private static memoryLeaseStore;
    /**
     * Helper: Resolves standard Web Crypto instance
     */
    private static getSubtleCrypto;
    /**
     * Helper: Checks if native browser IndexedDB is accessible
     */
    private static isIndexedDbAvailable;
    /**
     * Opens or initializes the IndexedDB database instance
     */
    private static openDatabase;
    /**
     * Retrieves existing non-exportable CryptoKey or generates a new one.
     * Key is generated with extractable=false so raw bytes cannot be exported.
     */
    static getOrCreateMasterKey(): Promise<CryptoKey>;
    /**
     * Encrypts and persists a verified session lease in the vault.
     */
    static saveLease(payload: CachedLeasePayload): Promise<void>;
    /**
     * Decrypts and retrieves the cached session lease from the vault.
     */
    static getLease(): Promise<CachedLeasePayload | null>;
    /**
     * Verifies if an active, non-expired offline grace lease exists for the current appId and origin.
     */
    static verifyOfflineLease(appId: string, currentOrigin: string): Promise<LeaseVerificationResult>;
    /**
     * Completely clears all keys and leases from the vault (used during remote threat remediation / WIPE_LOCAL_KEYS).
     */
    static clearVault(): Promise<void>;
    /**
     * Universal Base64 Helpers
     */
    private static bytesToBase64;
    private static base64ToBytes;
}
