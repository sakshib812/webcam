/**
 * SecurityLockoutOverlay: DOM Lockout & Threat Remediation Screen Overlay
 *
 * Renders an un-dismissible, high-contrast cyber security lockout shield over the DOM
 * when a critical threat is detected or a TERMINATE_APP / BLOCK_DEVICE directive is enforced.
 * Captures and suppresses all user input and interaction events.
 */
export declare class SecurityLockoutOverlay {
    static OVERLAY_ELEMENT_ID: string;
    private static isCapturingEvents;
    private static eventSuppressor;
    /**
     * Renders the full-screen lockout shield over document.body
     */
    static renderLockoutOverlay(title?: string, message?: string, incidentId?: string): void;
    /**
     * Safely dismisses the lockout overlay if present
     */
    static dismissLockoutOverlay(): void;
    /**
     * Checks if the lockout overlay is currently active in the DOM
     */
    static isLockoutActive(): boolean;
}
