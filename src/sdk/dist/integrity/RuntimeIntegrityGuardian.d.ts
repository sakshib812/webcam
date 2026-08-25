/**
 * RuntimeIntegrityGuardian: Prototype Hardening, Proxy Traps & Native API Integrity Guardian
 *
 * Web equivalent of Android native code integrity verification and syscall bootstrapping.
 * Protects JavaScript runtime intrinsics from monkey-patching, prototype pollution,
 * and rogue extension injection while maintaining pristine, unpoisonable function pointers.
 */
export interface TamperedApiItem {
    apiName: string;
    isNative: boolean;
    reason: string;
}
export interface RuntimeIntegrityReport {
    isClean: boolean;
    tamperedCount: number;
    tamperedApis: TamperedApiItem[];
    auditedCount: number;
}
export declare class RuntimeIntegrityGuardian {
    private static NATIVE_CODE_REGEX;
    /**
     * Exposes cached pristine intrinsics for internal SDK use
     */
    static pristine: {
        toString: () => string;
        defineProperty: <T>(o: T, p: PropertyKey, attributes: PropertyDescriptor & ThisType<any>) => T;
        freeze: {
            <T extends Function>(f: T): T;
            <T extends {
                [idx: string]: U | null | undefined | object;
            }, U extends string | bigint | number | boolean | symbol>(o: T): Readonly<T>;
            <T>(o: T): Readonly<T>;
        };
        getOwnPropertyDescriptor: (o: any, p: PropertyKey) => PropertyDescriptor | undefined;
        stringify: {
            (value: any, replacer?: (this: any, key: string, value: any) => any, space?: string | number): string;
            (value: any, replacer?: (number | string)[] | null, space?: string | number): string;
        };
        now: () => number;
    };
    /**
     * Evaluates whether a given function is a genuine C++ browser native function
     * rather than a userland wrapper, proxy, or closure.
     */
    static isNativeFunction(fn: any): boolean;
    /**
     * Recursively seals and freezes target ECMAScript built-in prototypes to block prototype pollution.
     */
    static freezePrototypes(targets?: any[]): {
        frozenCount: number;
        errors: string[];
    };
    /**
     * Wraps a sensitive SDK object or configuration in strict Proxy traps to prevent runtime mutation
     * from external userland scripts while allowing internal methods to operate on the raw instance.
     */
    static createTamperProofProxy<T extends object>(target: T, name?: string, onTamper?: (action: string, prop: string) => void): T;
    /**
     * Performs an active runtime audit of critical browser primitives to detect hooks and overrides.
     */
    static auditRuntimeIntegrity(): RuntimeIntegrityReport;
}
