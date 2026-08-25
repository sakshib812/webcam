/**
 * PayloadSecurityHelper: Web Crypto API End-to-End Encryption & Telemetry Envelope Manager
 *
 * Implements ephemeral ECDH (P-256/secp256r1) key agreement, RFC 5869 HKDF-SHA256 key derivation,
 * AES-256-GCM authenticated payload encryption, and HMAC-SHA256 envelope signing.
 *
 * Fully aligned with Android SDK (PayloadSecurityHelper.kt) and Portal Ingest Gateway (payload_security.js).
 */
import { MemoryScrubber } from './MemoryScrubber.js';
export class PayloadSecurityHelper {
    // Persistent Server EC Public Key (P-256 / prime256v1) X.509 SPKI Base64 matching .env
    static DEFAULT_SERVER_PUBLIC_KEY_BASE64 = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXWEHhyh0kWjfDiNepjvNZ3/9JVzVR/O8jiCAg4//pE2AWxh1k0+ezQfM4hOFLBGPS9GGbCfFXvp2XCYrMljJPw==';
    // 256-Bit HMAC Key Hex matching .env SECURESHIELD_HMAC_KEY
    static DEFAULT_HMAC_KEY_HEX = '519a30120b9fa916d17661342905a8b465c07d8eac7e01cb26df689620b4f166';
    static serverPublicKeyBase64 = PayloadSecurityHelper.DEFAULT_SERVER_PUBLIC_KEY_BASE64;
    static hmacKeyHex = PayloadSecurityHelper.DEFAULT_HMAC_KEY_HEX;
    static setServerPublicKey(base64PublicKey) {
        if (base64PublicKey && base64PublicKey.trim()) {
            PayloadSecurityHelper.serverPublicKeyBase64 = base64PublicKey.trim();
        }
    }
    static setHmacKey(hexHmacKey) {
        if (hexHmacKey && hexHmacKey.trim()) {
            PayloadSecurityHelper.hmacKeyHex = hexHmacKey.trim();
        }
    }
    /**
     * Helper: Resolves standard Web Crypto instance across Browser & Node environments
     */
    static getSubtleCrypto() {
        if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle) {
            return globalThis.crypto.subtle;
        }
        if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
            return window.crypto.subtle;
        }
        throw new Error('Web Crypto API (crypto.subtle) is not available in the current environment.');
    }
    /**
     * Helper: Fills a TypedArray buffer with zeros (best-effort JS memory scrubbing)
     */
    static scrubBuffer(buffer) {
        MemoryScrubber.zero(buffer);
    }
    /**
     * Binary Encoding Utilities (Universal Web standards, no Node Buffer required)
     */
    static bytesToBase64(bytes) {
        let binary = '';
        const len = bytes.byteLength;
        for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        if (typeof btoa === 'function') {
            return btoa(binary);
        }
        const nodeBuf = globalThis.Buffer;
        if (typeof nodeBuf !== 'undefined') {
            return nodeBuf.from(bytes).toString('base64');
        }
        throw new Error('Base64 encoding is not supported in this runtime.');
    }
    static base64ToBytes(base64) {
        const cleanB64 = base64.replace(/[\r\n\s]/g, '');
        if (typeof atob === 'function') {
            const binary = atob(cleanB64);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            return bytes;
        }
        const nodeBuf = globalThis.Buffer;
        if (typeof nodeBuf !== 'undefined') {
            return new Uint8Array(nodeBuf.from(cleanB64, 'base64'));
        }
        throw new Error('Base64 decoding is not supported in this runtime.');
    }
    static hexToBytes(hex) {
        const cleanHex = hex.replace(/[\r\n\s]/g, '');
        if (cleanHex.length % 2 !== 0) {
            throw new Error('Invalid hex string length');
        }
        const bytes = new Uint8Array(cleanHex.length / 2);
        for (let i = 0; i < cleanHex.length; i += 2) {
            bytes[i / 2] = parseInt(cleanHex.substring(i, i + 2), 16);
        }
        return bytes;
    }
    static bytesToHex(bytes) {
        let hex = '';
        for (let i = 0; i < bytes.length; i++) {
            hex += bytes[i].toString(16).padStart(2, '0');
        }
        return hex;
    }
    /**
     * Generates a cryptographically random UUID v4 string without dashes
     */
    static generateNonce() {
        if (typeof crypto !== 'undefined' && crypto.randomUUID) {
            return crypto.randomUUID().replace(/-/g, '');
        }
        const randomBytes = new Uint8Array(16);
        if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
            crypto.getRandomValues(randomBytes);
        }
        else {
            for (let i = 0; i < 16; i++) {
                randomBytes[i] = Math.floor(Math.random() * 256);
            }
        }
        return PayloadSecurityHelper.bytesToHex(randomBytes);
    }
    /**
     * Encrypts and cryptographically signs raw JSON telemetry report using End-to-End
     * ECDH-P256 Ephemeral Key Exchange + RFC 5869 HKDF-SHA256 + AES-256-GCM + HMAC-SHA256.
     *
     * @param rawJsonStr The raw JSON string containing the security audit report
     * @param customServerPubKeyBase64 Optional override for Server Public Key SPKI
     * @param customHmacKeyHex Optional override for HMAC Key Hex
     * @returns JSON string representing the full SecurityEnvelope
     */
    static async encryptAndSignPayload(rawJsonStr, customServerPubKeyBase64, customHmacKeyHex) {
        const envelope = await PayloadSecurityHelper.createSecurityEnvelope(rawJsonStr, customServerPubKeyBase64, customHmacKeyHex);
        return JSON.stringify(envelope);
    }
    /**
     * Constructs the structured SecurityEnvelope object
     */
    static async createSecurityEnvelope(rawJsonStr, customServerPubKeyBase64, customHmacKeyHex) {
        const subtle = PayloadSecurityHelper.getSubtleCrypto();
        const targetServerPubB64 = (customServerPubKeyBase64 && customServerPubKeyBase64.trim()) || PayloadSecurityHelper.serverPublicKeyBase64;
        const targetHmacKeyHex = (customHmacKeyHex && customHmacKeyHex.trim()) || PayloadSecurityHelper.hmacKeyHex;
        // 1. Generate Ephemeral Client KeyPair on P-256 (secp256r1 / prime256v1)
        const clientKeyPair = (await subtle.generateKey({
            name: 'ECDH',
            namedCurve: 'P-256'
        }, true, // extractable public key for export
        ['deriveBits', 'deriveKey']));
        // 2. Export Client Ephemeral Public Key in SPKI format
        const ephemeralPubSpkiBuffer = await subtle.exportKey('spki', clientKeyPair.publicKey);
        const ephemeralPubBase64 = PayloadSecurityHelper.bytesToBase64(new Uint8Array(ephemeralPubSpkiBuffer));
        // 3. Import Server Public Key (X.509 SPKI)
        const serverPubBytes = PayloadSecurityHelper.base64ToBytes(targetServerPubB64);
        const serverPublicKey = await subtle.importKey('spki', serverPubBytes, {
            name: 'ECDH',
            namedCurve: 'P-256'
        }, false, []);
        // 4. Compute Shared Secret via ECDH (256 bits)
        const sharedSecretBits = await subtle.deriveBits({
            name: 'ECDH',
            public: serverPublicKey
        }, clientKeyPair.privateKey, 256);
        // 5. Derive AES-256-GCM Key via HKDF-SHA256 (salt = nonce bytes, info = "secureshield_telemetry_v4")
        const nonce = PayloadSecurityHelper.generateNonce();
        const timestamp = Date.now();
        const encoder = new TextEncoder();
        const salt = encoder.encode(nonce);
        const info = encoder.encode('secureshield_telemetry_v4');
        const hkdfMasterKey = await subtle.importKey('raw', sharedSecretBits, { name: 'HKDF' }, false, ['deriveKey']);
        const aesKey = await subtle.deriveKey({
            name: 'HKDF',
            hash: 'SHA-256',
            salt: salt,
            info: info
        }, hkdfMasterKey, {
            name: 'AES-GCM',
            length: 256
        }, false, ['encrypt']);
        // Best-effort scrubbing of ephemeral raw secret bits in RAM
        PayloadSecurityHelper.scrubBuffer(new Uint8Array(sharedSecretBits));
        // 6. Encrypt with AES-256-GCM (12-byte IV, 128-bit authentication tag)
        const ivBytes = new Uint8Array(12);
        if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
            crypto.getRandomValues(ivBytes);
        }
        else {
            for (let i = 0; i < 12; i++) {
                ivBytes[i] = Math.floor(Math.random() * 256);
            }
        }
        const ivBase64 = PayloadSecurityHelper.bytesToBase64(ivBytes);
        const plaintextBytes = encoder.encode(rawJsonStr);
        const ciphertextWithTagBuffer = await subtle.encrypt({
            name: 'AES-GCM',
            iv: ivBytes,
            tagLength: 128
        }, aesKey, plaintextBytes);
        // Scrub plaintext buffer immediately after encryption
        PayloadSecurityHelper.scrubBuffer(plaintextBytes);
        PayloadSecurityHelper.scrubBuffer(ivBytes);
        const bodyBase64 = PayloadSecurityHelper.bytesToBase64(new Uint8Array(ciphertextWithTagBuffer));
        // 7. Compute HMAC-SHA256 signature matching portal formula:
        // signature = HMAC-SHA256("${bodyBase64}|${timestamp}|${ivBase64}|${nonce}")
        const hmacKeyBytes = PayloadSecurityHelper.hexToBytes(targetHmacKeyHex);
        const hmacCryptoKey = await subtle.importKey('raw', hmacKeyBytes, {
            name: 'HMAC',
            hash: 'SHA-256'
        }, false, ['sign']);
        const messageToSign = encoder.encode(`${bodyBase64}|${timestamp}|${ivBase64}|${nonce}`);
        const signatureBuffer = await subtle.sign('HMAC', hmacCryptoKey, messageToSign);
        const signatureHex = PayloadSecurityHelper.bytesToHex(new Uint8Array(signatureBuffer));
        // Best-effort scrubbing of HMAC raw key
        PayloadSecurityHelper.scrubBuffer(hmacKeyBytes);
        // 8. Assemble Full Security Envelope
        return {
            header: {
                signature: signatureHex,
                timestamp,
                iv: ivBase64,
                nonce,
                ephemeral_pub_key: ephemeralPubBase64,
                crypto_mode: 'ECDH-P256-AES-GCM'
            },
            body: bodyBase64
        };
    }
}
