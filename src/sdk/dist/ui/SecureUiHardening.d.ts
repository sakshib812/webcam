/**
 * SecureUiHardening: DOM Input Hardening, Leak Mitigation & Dynamic Security Watermarking
 *
 * Provides client-side defense in depth against UI scraping, physical camera photo leaks,
 * and browser form field credential caching.
 */
export interface WatermarkOptions {
    opacity?: number;
    color?: string;
    fontSize?: number;
    elementId?: string;
}
export declare class SecureUiHardening {
    static DEFAULT_WATERMARK_ID: string;
    /**
     * Renders a non-intrusive diagonal repeating security watermark across the entire browser viewport.
     */
    static renderSecurityWatermark(watermarkText?: string, options?: WatermarkOptions): void;
    /**
     * Removes the active security watermark from the DOM.
     */
    static removeSecurityWatermark(elementId?: string): void;
    /**
     * Hardens form input elements against browser caching, autofill exfiltration, and spellcheck sniffing.
     */
    static protectFormFields(containerSelector?: string): void;
}
