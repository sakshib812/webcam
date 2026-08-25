/**
 * SecureClipboard: Timed Auto-Wipe & Sensitive Input Exfiltration Shield
 *
 * Web equivalent of Android KeyStore clipboard data scrubbing.
 * Allows applications to place sensitive data (OTP codes, private keys, credit cards)
 * on the system clipboard with an automated time-to-live (TTL) auto-wipe timer.
 */
export interface ClipboardCopyResult {
    success: boolean;
    wipeAfterMs: number;
    cancelWipe: () => void;
}
export declare class SecureClipboard {
    private static activeWipeTimer;
    private static lastCopiedSensitiveHash;
    /**
     * Writes sensitive text to the clipboard and starts an automatic wipe countdown timer.
     */
    static copy(text: string, wipeAfterMs?: number): Promise<ClipboardCopyResult>;
    /**
     * Immediately clears/overwrites the system clipboard.
     */
    static wipeNow(): Promise<boolean>;
    /**
     * Cancels any pending auto-wipe countdown timer.
     */
    static cancelActiveWipe(): void;
    /**
     * Hardens designated sensitive input elements against unauthorized cut/copy/drag exfiltration.
     */
    static protectSensitiveInputs(selector?: string): void;
}
