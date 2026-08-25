/**
 * SecurityLockoutOverlay: DOM Lockout & Threat Remediation Screen Overlay
 *
 * Renders an un-dismissible, high-contrast cyber security lockout shield over the DOM
 * when a critical threat is detected or a TERMINATE_APP / BLOCK_DEVICE directive is enforced.
 * Captures and suppresses all user input and interaction events.
 */
export class SecurityLockoutOverlay {
    static OVERLAY_ELEMENT_ID = 'secureshield_lockout_overlay';
    static isCapturingEvents = false;
    static eventSuppressor = (e) => {
        e.stopPropagation();
        e.preventDefault();
    };
    /**
     * Renders the full-screen lockout shield over document.body
     */
    static renderLockoutOverlay(title = '🚨 Access Terminated: Security Violation', message = 'Your application session has been terminated by enterprise security policy due to an active environment threat.', incidentId) {
        if (typeof document === 'undefined' || !document.body || typeof document.getElementById !== 'function') {
            return;
        }
        // Check if overlay already active
        if (document.getElementById(SecurityLockoutOverlay.OVERLAY_ELEMENT_ID)) {
            return;
        }
        const overlay = document.createElement('div');
        overlay.id = SecurityLockoutOverlay.OVERLAY_ELEMENT_ID;
        overlay.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100vw;
      height: 100vh;
      background: #0B0F19;
      color: #F8FAFC;
      z-index: 2147483647;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      text-align: center;
      padding: 24px;
      box-sizing: border-box;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      user-select: none;
      -webkit-user-select: none;
    `;
        const timestampStr = new Date().toISOString();
        const incId = incidentId || `INC-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 1000)}`;
        overlay.innerHTML = `
      <div style="max-width: 520px; background: #131B2E; border: 1px solid #EF4444; border-radius: 16px; padding: 36px 28px; box-shadow: 0 25px 50px -12px rgba(239, 68, 68, 0.25);">
        <div style="font-size: 56px; line-height: 1; margin-bottom: 18px;">🛡️</div>
        <h1 style="color: #F87171; font-size: 20px; font-weight: 800; margin: 0 0 12px 0; letter-spacing: -0.02em;">
          ${title}
        </h1>
        <p style="color: #94A3B8; font-size: 13px; line-height: 1.6; margin: 0 0 24px 0;">
          ${message}
        </p>
        <div style="background: #0B0F19; border: 1px solid #1E293B; border-radius: 8px; padding: 12px; margin-bottom: 24px; text-align: left;">
          <div style="color: #64748B; font-size: 11px; font-family: monospace; margin-bottom: 4px;">INCIDENT ID: <span style="color: #00E5FF;">${incId}</span></div>
          <div style="color: #64748B; font-size: 11px; font-family: monospace;">TIMESTAMP: <span style="color: #94A3B8;">${timestampStr}</span></div>
          <div style="color: #64748B; font-size: 11px; font-family: monospace; margin-top: 4px;">ENFORCEMENT: <span style="color: #EF4444; font-weight: bold;">BLOCK_TERMINATE</span></div>
        </div>
        <div style="font-size: 11px; color: #475569; font-weight: 500;">
          Protected by SecureShield Enterprise Defense
        </div>
      </div>
    `;
        try {
            document.body.appendChild(overlay);
            document.body.style.overflow = 'hidden';
        }
        catch {
            // Ignore if DOM attachment fails
        }
        // Suppress all keyboard/mouse/touch interactions
        if (!SecurityLockoutOverlay.isCapturingEvents && typeof window !== 'undefined') {
            const eventTypes = ['click', 'dblclick', 'mousedown', 'mouseup', 'keydown', 'keyup', 'keypress', 'touchstart', 'touchend', 'contextmenu'];
            for (const ev of eventTypes) {
                window.addEventListener(ev, SecurityLockoutOverlay.eventSuppressor, true);
            }
            SecurityLockoutOverlay.isCapturingEvents = true;
        }
    }
    /**
     * Safely dismisses the lockout overlay if present
     */
    static dismissLockoutOverlay() {
        if (typeof document !== 'undefined' && typeof document.getElementById === 'function') {
            const el = document.getElementById(SecurityLockoutOverlay.OVERLAY_ELEMENT_ID);
            if (el && el.parentNode) {
                el.parentNode.removeChild(el);
            }
            if (document.body) {
                document.body.style.overflow = '';
            }
        }
        if (SecurityLockoutOverlay.isCapturingEvents && typeof window !== 'undefined') {
            const eventTypes = ['click', 'dblclick', 'mousedown', 'mouseup', 'keydown', 'keyup', 'keypress', 'touchstart', 'touchend', 'contextmenu'];
            for (const ev of eventTypes) {
                window.removeEventListener(ev, SecurityLockoutOverlay.eventSuppressor, true);
            }
            SecurityLockoutOverlay.isCapturingEvents = false;
        }
    }
    /**
     * Checks if the lockout overlay is currently active in the DOM
     */
    static isLockoutActive() {
        if (typeof document === 'undefined' || typeof document.getElementById !== 'function')
            return false;
        return !!document.getElementById(SecurityLockoutOverlay.OVERLAY_ELEMENT_ID);
    }
}
