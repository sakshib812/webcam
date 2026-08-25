/**
 * PayloadSecurityHelper: Web Crypto API End-to-End Encryption & Telemetry Envelope Manager
 *
 * Implements ephemeral ECDH (P-256/secp256r1) key agreement, RFC 5869 HKDF-SHA256 key derivation,
 * AES-256-GCM authenticated payload encryption, and HMAC-SHA256 envelope signing.
 *
 * Fully aligned with Android SDK (PayloadSecurityHelper.kt) and Portal Ingest Gateway (payload_security.js).
 */
export interface SecurityEnvelopeHeader {
    signature: string;
    timestamp: number;
    iv: string;
    nonce: string;
    ephemeral_pub_key: string;
    crypto_mode: string;
}
export interface SecurityEnvelope {
    header: SecurityEnvelopeHeader;
    body: string;
}
export declare class PayloadSecurityHelper {
    static DEFAULT_SERVER_PUBLIC_KEY_BASE64: string;
    static DEFAULT_HMAC_KEY_HEX: string;
    private static serverPublicKeyBase64;
    private static hmacKeyHex;
    static setServerPublicKey(base64PublicKey: string): void;
    static setHmacKey(hexHmacKey: string): void;
    /**
     * Helper: Resolves standard Web Crypto instance across Browser & Node environments
     */
    private static getSubtleCrypto;
    /**
     * Helper: Fills a TypedArray buffer with zeros (best-effort JS memory scrubbing)
     */
    static scrubBuffer(buffer: ArrayBufferView | ArrayBuffer): void;
    /**
     * Binary Encoding Utilities (Universal Web standards, no Node Buffer required)
     */
    static bytesToBase64(bytes: Uint8Array): string;
    static base64ToBytes(base64: string): Uint8Array;
    static hexToBytes(hex: string): Uint8Array;
    static bytesToHex(bytes: Uint8Array): string;
    /**
     * Generates a cryptographically random UUID v4 string without dashes
     */
    static generateNonce(): string;
    /**
     * Encrypts and cryptographically signs raw JSON telemetry report using End-to-End
     * ECDH-P256 Ephemeral Key Exchange + RFC 5869 HKDF-SHA256 + AES-256-GCM + HMAC-SHA256.
     *
     * @param rawJsonStr The raw JSON string containing the security audit report
     * @param customServerPubKeyBase64 Optional override for Server Public Key SPKI
     * @param customHmacKeyHex Optional override for HMAC Key Hex
     * @returns JSON string representing the full SecurityEnvelope
     */
    static encryptAndSignPayload(rawJsonStr: string, customServerPubKeyBase64?: string, customHmacKeyHex?: string): Promise<string>;
    /**
     * Constructs the structured SecurityEnvelope object
     */
    static createSecurityEnvelope(rawJsonStr: string, customServerPubKeyBase64?: string, customHmacKeyHex?: string): Promise<SecurityEnvelope>;
}
