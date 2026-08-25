/**
 * OriginValidator: Browser Origin, Domain Whitelisting & Frame Security Validator
 *
 * Validates the runtime execution context against authorized domain configurations,
 * supports wildcard subdomain patterns, and checks for unauthorized framing/clickjacking.
 */
export class OriginValidator {
    /**
     * Normalizes an origin/domain string by stripping protocol, port, path, and trailing slashes.
     */
    static normalizeDomain(input) {
        if (!input || typeof input !== 'string')
            return '';
        return input
            .trim()
            .toLowerCase()
            .replace(/^https?:\/\//, '')
            .replace(/:[0-9]+$/, '')
            .replace(/\/.*$/, '')
            .trim();
    }
    /**
     * Checks if current hostname matches a target domain or wildcard rule (e.g. *.secureshield.io)
     */
    static matchesDomain(currentHostname, targetPattern) {
        const current = OriginValidator.normalizeDomain(currentHostname);
        const target = OriginValidator.normalizeDomain(targetPattern);
        if (!current || !target)
            return false;
        // Exact match (e.g., "app.secureshield.io" === "app.secureshield.io", "localhost" === "localhost")
        if (current === target)
            return true;
        // Wildcard match (e.g., "*.secureshield.io" or ".secureshield.io" matches "portal.secureshield.io")
        if (target.startsWith('*.')) {
            const rootDomain = target.substring(2);
            return current.endsWith(`.${rootDomain}`) || current === rootDomain;
        }
        if (target.startsWith('.')) {
            const rootDomain = target.substring(1);
            return current.endsWith(`.${rootDomain}`) || current === rootDomain;
        }
        return false;
    }
    /**
     * Detects if the current window is being rendered inside an iframe
     */
    static isFramed() {
        try {
            if (typeof window === 'undefined')
                return false;
            return window.self !== window.top;
        }
        catch {
            // Access to window.top blocked by cross-origin security policy -> Definitively framed cross-origin!
            return true;
        }
    }
    /**
     * Resolves the current runtime origin & hostname
     */
    static getCurrentContext() {
        if (typeof window !== 'undefined' && window.location) {
            const origin = window.location.origin || `${window.location.protocol}//${window.location.host}`;
            const hostname = window.location.hostname || 'localhost';
            return { origin, hostname };
        }
        return { origin: 'http://localhost:3000', hostname: 'localhost' };
    }
    /**
     * Validates current browser execution origin against registered allowlist
     */
    static validate(allowedOrigins) {
        const { origin, hostname } = OriginValidator.getCurrentContext();
        const isFramed = OriginValidator.isFramed();
        if (!allowedOrigins || allowedOrigins.length === 0) {
            return {
                isValid: true,
                currentOrigin: origin,
                currentHostname: hostname,
                isFramed
            };
        }
        const isMatch = allowedOrigins.some(rule => OriginValidator.matchesDomain(hostname, rule) || OriginValidator.matchesDomain(origin, rule));
        if (!isMatch) {
            return {
                isValid: false,
                currentOrigin: origin,
                currentHostname: hostname,
                isFramed,
                mismatchReason: `Current origin '${origin}' (${hostname}) does not match any allowed domain in allowlist: [${allowedOrigins.join(', ')}]`
            };
        }
        return {
            isValid: true,
            currentOrigin: origin,
            currentHostname: hostname,
            isFramed
        };
    }
}
