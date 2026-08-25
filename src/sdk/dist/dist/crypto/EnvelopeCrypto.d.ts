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
/**
 * Encrypts a plaintext string using AES-256-GCM into the standard envelope format.
 * @param plaintext Plaintext UTF-8 string to encrypt
 * @param keyBase64 32-byte Encryption Key in Base64
 * @returns Serialized envelope string: enc:v1:<iv_hex>:<tag_hex>:<ciphertext_hex>
 */
export declare function envelopeEncrypt(plaintext: string, keyBase64: string): Promise<string>;
/**
 * Decrypts a standard envelope string into plaintext UTF-8.
 * @param envelopeString Serialized envelope string: enc:v1:<iv_hex>:<tag_hex>:<ciphertext_hex>
 * @param keyBase64 32-byte Encryption Key in Base64
 * @returns Plaintext UTF-8 string
 */
export declare function envelopeDecrypt(envelopeString: string, keyBase64: string): Promise<string>;
