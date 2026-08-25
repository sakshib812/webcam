/**
 * TabBlurShield: Browser Tab Switcher & Visibility Privacy Shield
 *
 * Web equivalent of Android FLAG_SECURE / recent-apps snapshot masking.
 * Automatically obscures confidential DOM data when the tab is blurred, minimized, or switched,
 * preventing shoulder surfing, OS window switcher thumbnail leakage, and screen recording capture.
 */
export interface TabBlurOptions {
    blurFilter?: string;
    maskMessage?: string;
    maskSubtitle?: string;
    listenToWindowBlur?: boolean;
    customOverlayId?: string;
}
export declare class TabBlurShield {
    static DEFAULT_OVERLAY_ID: string;
    private static activeOptions;
    private static isListening;
    private static isCurrentlyMasked;
    private static onVisibilityChangeHandler;
    private static onWindowBlurHandler;
    private static onWindowFocusHandler;
    /**
     * Enables automatic tab blur & visibilitychange masking.
     */
    static enable(options?: TabBlurOptions): void;
    /**
     * Disables tab blur masking and restores DOM visibility.
     */
    static disable(): void;
    /**
     * Mounts the privacy blur shield over the viewport.
     */
    static mask(): void;
    /**
     * Unmasks and removes the privacy blur shield.
     */
    static unmask(): void;
    static isMasked(): boolean;
    static isEnabled(): boolean;
}
