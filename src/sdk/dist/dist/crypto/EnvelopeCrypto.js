/**
 * SecureShield Web SDK - Shared Key-Parameterized Envelope Crypto Engine
 *
 * Implements WebCrypto SubtleCrypto AES-256-GCM authenticated encryption/decryption
 * adhering to the unified wire format:
 *   enc:v1:<iv_hex>:<tag_hex>:<ciphertext_hex>
 *
 * Wire format specifications:
 *   - Version: enc:v1
 *   - Algorithm: AES-256-GCM
 *   - IV: 12 bytes (96 bits) cryptographically random, hex encoded
 *   - Tag: 16 bytes (128 bits) authentication tag, hex encoded
 *   - Ciphertext: Variable length, hex encoded
 *
 * ACCEPTED TRADE-OFF: Possession of a tenant's Header Key + Encryption Key + a valid Initialization Key
 * is sufficient to authenticate as that tenant/app from any device, since nothing at runtime re-verifies
 * package identity or signing cert.
 */
function getSubtleCrypto() {
    if (typeof globalThis !== 'undefined' && globalThis.crypto?.subtle) {
        return globalThis.crypto.subtle;
    }
    if (typeof window !== 'undefined' && window.crypto?.subtle) {
        return window.crypto.subtle;
    }
    throw new Error('[SecureShield EnvelopeCrypto] WebCrypto SubtleCrypto is not available in current environment.');
}
function getRandomValues(array) {
    if (typeof globalThis !== 'undefined' && globalThis.crypto?.getRandomValues) {
        return globalThis.crypto.getRandomValues(array);
    }
    if (typeof window !== 'undefined' && window.crypto?.getRandomValues) {
        return window.crypto.getRandomValues(array);
    }
    throw new Error('[SecureShield EnvelopeCrypto] WebCrypto getRandomValues is not available.');
}
function bufToHex(buffer) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
        hex += bytes[i].toString(16).padStart(2, '0');
    }
    return hex;
}
function hexToUint8Array(hexString) {
    if (hexString.length % 2 !== 0) {
        throw new Error('[SecureShield EnvelopeCrypto] Invalid hex string length');
    }
    const bytes = new Uint8Array(hexString.length / 2);
    for (let i = 0; i < hexString.length; i += 2) {
        bytes[i / 2] = parseInt(hexString.substring(i, i + 2), 16);
    }
    return bytes;
}
function base64ToUint8Array(base64) {
    // Support both browser atob and Node Buffer if running in tests
    if (typeof atob === 'function') {
        const binaryString = atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes;
    }
    const maybeBuffer = globalThis.Buffer;
    if (typeof maybeBuffer !== 'undefined') {
        return new Uint8Array(maybeBuffer.from(base64, 'base64'));
    }
    throw new Error('[SecureShield EnvelopeCrypto] Base64 decoding not available.');
}
/**
 * Encrypts a plaintext string using AES-256-GCM into the standard envelope format.
 * @param plaintext Plaintext UTF-8 string to encrypt
 * @param keyBase64 32-byte Encryption Key in Base64
 * @returns Serialized envelope string: enc:v1:<iv_hex>:<tag_hex>:<ciphertext_hex>
 */
export async function envelopeEncrypt(plaintext, keyBase64) {
    const subtle = getSubtleCrypto();
    const keyBytes = base64ToUint8Array(keyBase64);
    if (keyBytes.length !== 32) {
        throw new Error(`[SecureShield EnvelopeCrypto] Invalid key length. Expected 32 bytes for AES-256-GCM, got ${keyBytes.length}`);
    }
    const cryptoKey = await subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
    const iv = getRandomValues(new Uint8Array(12));
    const encoder = new TextEncoder();
    const encodedPlaintext = encoder.encode(plaintext);
    // SubtleCrypto appends the 16-byte authentication tag to the end of the ciphertext
    const encryptedBuffer = await subtle.encrypt({
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128
    }, cryptoKey, encodedPlaintext);
    const encryptedBytes = new Uint8Array(encryptedBuffer);
    const tagLength = 16;
    const ciphertextLength = encryptedBytes.length - tagLength;
    const ciphertextBytes = encryptedBytes.subarray(0, ciphertextLength);
    const tagBytes = encryptedBytes.subarray(ciphertextLength);
    const ivHex = bufToHex(iv);
    const tagHex = bufToHex(tagBytes);
    const ciphertextHex = bufToHex(ciphertextBytes);
    return `enc:v1:${ivHex}:${tagHex}:${ciphertextHex}`;
}
/**
 * Decrypts a standard envelope string into plaintext UTF-8.
 * @param envelopeString Serialized envelope string: enc:v1:<iv_hex>:<tag_hex>:<ciphertext_hex>
 * @param keyBase64 32-byte Encryption Key in Base64
 * @returns Plaintext UTF-8 string
 */
export async function envelopeDecrypt(envelopeString, keyBase64) {
    const subtle = getSubtleCrypto();
    const parts = envelopeString.split(':');
    if (parts.length !== 5 || parts[0] !== 'enc' || parts[1] !== 'v1') {
        throw new Error('[SecureShield EnvelopeCrypto] Invalid envelope format. Expected enc:v1:<iv>:<tag>:<ciphertext>');
    }
    const ivHex = parts[2];
    const tagHex = parts[3];
    const ciphertextHex = parts[4];
    const iv = hexToUint8Array(ivHex);
    const tag = hexToUint8Array(tagHex);
    const ciphertext = hexToUint8Array(ciphertextHex);
    if (iv.length !== 12) {
        throw new Error(`[SecureShield EnvelopeCrypto] Invalid IV length. Expected 12 bytes, got ${iv.length}`);
    }
    if (tag.length !== 16) {
        throw new Error(`[SecureShield EnvelopeCrypto] Invalid Auth Tag length. Expected 16 bytes, got ${tag.length}`);
    }
    const keyBytes = base64ToUint8Array(keyBase64);
    if (keyBytes.length !== 32) {
        throw new Error(`[SecureShield EnvelopeCrypto] Invalid key length. Expected 32 bytes for AES-256-GCM, got ${keyBytes.length}`);
    }
    const cryptoKey = await subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
    // SubtleCrypto decrypt expects ciphertext + tag concatenated
    const combinedBuffer = new Uint8Array(ciphertext.length + tag.length);
    combinedBuffer.set(ciphertext, 0);
    combinedBuffer.set(tag, ciphertext.length);
    const decryptedBuffer = await subtle.decrypt({
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128
    }, cryptoKey, combinedBuffer);
    const decoder = new TextDecoder();
    return decoder.decode(decryptedBuffer);
}
