/**
 * SecureUiHardening: DOM Input Hardening, Leak Mitigation & Dynamic Security Watermarking
 *
 * Provides client-side defense in depth against UI scraping, physical camera photo leaks,
 * and browser form field credential caching.
 */
export class SecureUiHardening {
    static DEFAULT_WATERMARK_ID = 'secureshield_security_watermark';
    /**
     * Renders a non-intrusive diagonal repeating security watermark across the entire browser viewport.
     */
    static renderSecurityWatermark(watermarkText = 'SECURESHIELD CONFIDENTIAL', options) {
        if (typeof document === 'undefined' || !document.body || typeof document.getElementById !== 'function') {
            return;
        }
        const elementId = options?.elementId || SecureUiHardening.DEFAULT_WATERMARK_ID;
        if (document.getElementById(elementId)) {
            SecureUiHardening.removeSecurityWatermark(elementId);
        }
        const opacity = options?.opacity ?? 0.08;
        const color = options?.color || '#00E5FF';
        const fontSize = options?.fontSize || 14;
        const watermarkSvg = `
      <svg xmlns="http://www.w3.org/2000/svg" width="300" height="150" viewBox="0 0 300 150">
        <text x="50%" y="50%" fill="${color}" font-family="monospace" font-size="${fontSize}" font-weight="bold" text-anchor="middle" transform="rotate(-25 150 75)" opacity="${opacity}">
          ${watermarkText}
        </text>
      </svg>
    `;
        const svgB64 = (typeof btoa === 'function')
            ? btoa(unescape(encodeURIComponent(watermarkSvg)))
            : '';
        const watermarkDiv = document.createElement('div');
        watermarkDiv.id = elementId;
        watermarkDiv.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100vw;
      height: 100vh;
      pointer-events: none;
      user-select: none;
      -webkit-user-select: none;
      z-index: 2147483645;
      background-repeat: repeat;
      background-image: url('data:image/svg+xml;base64,${svgB64}');
    `;
        try {
            document.body.appendChild(watermarkDiv);
        }
        catch {
            // Ignore attachment error
        }
    }
    /**
     * Removes the active security watermark from the DOM.
     */
    static removeSecurityWatermark(elementId = SecureUiHardening.DEFAULT_WATERMARK_ID) {
        if (typeof document !== 'undefined' && typeof document.getElementById === 'function') {
            const el = document.getElementById(elementId);
            if (el && el.parentNode) {
                el.parentNode.removeChild(el);
            }
        }
    }
    /**
     * Hardens form input elements against browser caching, autofill exfiltration, and spellcheck sniffing.
     */
    static protectFormFields(containerSelector) {
        if (typeof document === 'undefined' || typeof document.querySelectorAll !== 'function') {
            return;
        }
        try {
            const root = containerSelector ? document.querySelector(containerSelector) : document;
            if (!root)
                return;
            const inputs = root.querySelectorAll('input, textarea');
            inputs.forEach((el) => {
                el.setAttribute('autocomplete', 'off');
                el.setAttribute('autocorrect', 'off');
                el.setAttribute('autocapitalize', 'off');
                el.setAttribute('spellcheck', 'false');
                el.setAttribute('data-secureshield-hardened', 'true');
            });
        }
        catch {
            // Ignore query error
        }
    }
}
