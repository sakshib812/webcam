/**
 * OriginValidator: Browser Origin, Domain Whitelisting & Frame Security Validator
 *
 * Validates the runtime execution context against authorized domain configurations,
 * supports wildcard subdomain patterns, and checks for unauthorized framing/clickjacking.
 */
export interface OriginValidationResult {
    isValid: boolean;
    currentOrigin: string;
    currentHostname: string;
    isFramed: boolean;
    mismatchReason?: string;
}
export declare class OriginValidator {
    /**
     * Normalizes an origin/domain string by stripping protocol, port, path, and trailing slashes.
     */
    static normalizeDomain(input: string): string;
    /**
     * Checks if current hostname matches a target domain or wildcard rule (e.g. *.secureshield.io)
     */
    static matchesDomain(currentHostname: string, targetPattern: string): boolean;
    /**
     * Detects if the current window is being rendered inside an iframe
     */
    static isFramed(): boolean;
    /**
     * Resolves the current runtime origin & hostname
     */
    static getCurrentContext(): {
        origin: string;
        hostname: string;
    };
    /**
     * Validates current browser execution origin against registered allowlist
     */
    static validate(allowedOrigins?: string[]): OriginValidationResult;
}
