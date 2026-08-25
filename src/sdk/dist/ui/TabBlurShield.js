/**
 * TabBlurShield: Browser Tab Switcher & Visibility Privacy Shield
 *
 * Web equivalent of Android FLAG_SECURE / recent-apps snapshot masking.
 * Automatically obscures confidential DOM data when the tab is blurred, minimized, or switched,
 * preventing shoulder surfing, OS window switcher thumbnail leakage, and screen recording capture.
 */
export class TabBlurShield {
    static DEFAULT_OVERLAY_ID = 'secureshield_tab_privacy_shield';
    static activeOptions = {};
    static isListening = false;
    static isCurrentlyMasked = false;
    static onVisibilityChangeHandler = () => {
        if (typeof document === 'undefined')
            return;
        if (document.hidden) {
            TabBlurShield.mask();
        }
        else {
            TabBlurShield.unmask();
        }
    };
    static onWindowBlurHandler = () => {
        if (TabBlurShield.activeOptions.listenToWindowBlur) {
            TabBlurShield.mask();
        }
    };
    static onWindowFocusHandler = () => {
        if (typeof document !== 'undefined' && !document.hidden) {
            TabBlurShield.unmask();
        }
    };
    /**
     * Enables automatic tab blur & visibilitychange masking.
     */
    static enable(options) {
        TabBlurShield.activeOptions = {
            blurFilter: options?.blurFilter || 'blur(20px)',
            maskMessage: options?.maskMessage || '🛡️ Session Obscured for Privacy',
            maskSubtitle: options?.maskSubtitle || 'Return to tab to resume active session',
            listenToWindowBlur: options?.listenToWindowBlur ?? false, // Default false to avoid jarring masks during devtools clicks
            customOverlayId: options?.customOverlayId || TabBlurShield.DEFAULT_OVERLAY_ID
        };
        if (TabBlurShield.isListening) {
            return;
        }
        if (typeof document !== 'undefined' && typeof document.addEventListener === 'function') {
            document.addEventListener('visibilitychange', TabBlurShield.onVisibilityChangeHandler);
        }
        if (typeof window !== 'undefined' && typeof window.addEventListener === 'function') {
            if (TabBlurShield.activeOptions.listenToWindowBlur) {
                window.addEventListener('blur', TabBlurShield.onWindowBlurHandler);
                window.addEventListener('focus', TabBlurShield.onWindowFocusHandler);
            }
        }
        TabBlurShield.isListening = true;
    }
    /**
     * Disables tab blur masking and restores DOM visibility.
     */
    static disable() {
        if (typeof document !== 'undefined' && typeof document.removeEventListener === 'function') {
            document.removeEventListener('visibilitychange', TabBlurShield.onVisibilityChangeHandler);
        }
        if (typeof window !== 'undefined' && typeof window.removeEventListener === 'function') {
            window.removeEventListener('blur', TabBlurShield.onWindowBlurHandler);
            window.removeEventListener('focus', TabBlurShield.onWindowFocusHandler);
        }
        TabBlurShield.unmask();
        TabBlurShield.isListening = false;
    }
    /**
     * Mounts the privacy blur shield over the viewport.
     */
    static mask() {
        if (typeof document === 'undefined' || !document.body || typeof document.getElementById !== 'function') {
            TabBlurShield.isCurrentlyMasked = true;
            return;
        }
        const overlayId = TabBlurShield.activeOptions.customOverlayId || TabBlurShield.DEFAULT_OVERLAY_ID;
        if (document.getElementById(overlayId)) {
            return;
        }
        const overlay = document.createElement('div');
        overlay.id = overlayId;
        overlay.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100vw;
      height: 100vh;
      background: rgba(11, 15, 25, 0.88);
      backdrop-filter: ${TabBlurShield.activeOptions.blurFilter || 'blur(20px)'};
      -webkit-backdrop-filter: ${TabBlurShield.activeOptions.blurFilter || 'blur(20px)'};
      z-index: 2147483646;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      color: #F8FAFC;
      text-align: center;
      padding: 20px;
      box-sizing: border-box;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      user-select: none;
      -webkit-user-select: none;
      transition: opacity 0.15s ease-in-out;
    `;
        overlay.innerHTML = `
      <div style="background: rgba(19, 27, 46, 0.9); border: 1px solid rgba(0, 229, 255, 0.3); border-radius: 14px; padding: 28px 24px; max-width: 400px; box-shadow: 0 20px 40px rgba(0,0,0,0.5);">
        <div style="font-size: 42px; margin-bottom: 12px;">🛡️</div>
        <h3 style="margin: 0 0 8px 0; font-size: 16px; font-weight: 700; color: #38BDF8;">
          ${TabBlurShield.activeOptions.maskMessage}
        </h3>
        <p style="margin: 0; font-size: 12px; color: #94A3B8;">
          ${TabBlurShield.activeOptions.maskSubtitle}
        </p>
      </div>
    `;
        try {
            document.body.appendChild(overlay);
        }
        catch {
            // Ignore attachment error
        }
        TabBlurShield.isCurrentlyMasked = true;
    }
    /**
     * Unmasks and removes the privacy blur shield.
     */
    static unmask() {
        if (typeof document !== 'undefined' && typeof document.getElementById === 'function') {
            const overlayId = TabBlurShield.activeOptions.customOverlayId || TabBlurShield.DEFAULT_OVERLAY_ID;
            const el = document.getElementById(overlayId);
            if (el && el.parentNode) {
                el.parentNode.removeChild(el);
            }
        }
        TabBlurShield.isCurrentlyMasked = false;
    }
    static isMasked() {
        return TabBlurShield.isCurrentlyMasked;
    }
    static isEnabled() {
        return TabBlurShield.isListening;
    }
}
