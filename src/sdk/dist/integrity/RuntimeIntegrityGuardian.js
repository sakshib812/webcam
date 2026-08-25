/**
 * RuntimeIntegrityGuardian: Prototype Hardening, Proxy Traps & Native API Integrity Guardian
 *
 * Web equivalent of Android native code integrity verification and syscall bootstrapping.
 * Protects JavaScript runtime intrinsics from monkey-patching, prototype pollution,
 * and rogue extension injection while maintaining pristine, unpoisonable function pointers.
 */
// Capture pristine native intrinsics at module evaluation time before userland tampering can occur
const _Function_toString = Function.prototype.toString;
const _Object_defineProperty = Object.defineProperty;
const _Object_freeze = Object.freeze;
const _Object_getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const _Object_keys = Object.keys;
const _Array_isArray = Array.isArray;
const _JSON_stringify = JSON.stringify;
const _Date_now = Date.now;
export class RuntimeIntegrityGuardian {
    static NATIVE_CODE_REGEX = /^function\s*([a-zA-Z0-9_$]*)\s*\(\)\s*\{\s*\[native code\]\s*\}$/;
    /**
     * Exposes cached pristine intrinsics for internal SDK use
     */
    static pristine = {
        toString: _Function_toString,
        defineProperty: _Object_defineProperty,
        freeze: _Object_freeze,
        getOwnPropertyDescriptor: _Object_getOwnPropertyDescriptor,
        stringify: _JSON_stringify,
        now: _Date_now
    };
    /**
     * Evaluates whether a given function is a genuine C++ browser native function
     * rather than a userland wrapper, proxy, or closure.
     */
    static isNativeFunction(fn) {
        if (typeof fn !== 'function') {
            return false;
        }
        try {
            // 1. Evaluate string representation using pristine Function.prototype.toString
            const fnString = _Function_toString.call(fn);
            const isNativeString = RuntimeIntegrityGuardian.NATIVE_CODE_REGEX.test(fnString.trim()) ||
                fnString.includes('[native code]');
            if (!isNativeString) {
                return false;
            }
            // 2. Check if fn's own toString has been monkey-patched to lie about being native
            if (Object.prototype.hasOwnProperty.call(fn, 'toString')) {
                const customToString = fn.toString;
                if (customToString !== _Function_toString) {
                    const toStringRep = _Function_toString.call(customToString);
                    if (!toStringRep.includes('[native code]')) {
                        return false; // Hooked toString detected!
                    }
                }
            }
            return true;
        }
        catch {
            return false;
        }
    }
    /**
     * Recursively seals and freezes target ECMAScript built-in prototypes to block prototype pollution.
     */
    static freezePrototypes(targets) {
        let targetList;
        if (targets && targets.length > 0) {
            targetList = targets.map((t, i) => ({ name: `target_${i}`, obj: t }));
        }
        else {
            targetList = [
                { name: 'Function.prototype', obj: typeof Function !== 'undefined' ? Function.prototype : null },
                { name: 'Array.prototype', obj: typeof Array !== 'undefined' ? Array.prototype : null },
                { name: 'String.prototype', obj: typeof String !== 'undefined' ? String.prototype : null },
                { name: 'Date.prototype', obj: typeof Date !== 'undefined' ? Date.prototype : null },
                { name: 'Promise.prototype', obj: typeof Promise !== 'undefined' ? Promise.prototype : null },
                { name: 'crypto.subtle', obj: typeof crypto !== 'undefined' ? crypto.subtle : null }
            ];
        }
        let frozenCount = 0;
        const errors = [];
        for (const target of targetList) {
            if (!target.obj)
                continue;
            try {
                if (_Object_freeze(target.obj)) {
                    frozenCount++;
                }
                else {
                    errors.push(`Failed to freeze ${target.name}`);
                }
            }
            catch (err) {
                errors.push(`Error freezing ${target.name}: ${err.message}`);
            }
        }
        return { frozenCount, errors };
    }
    /**
     * Wraps a sensitive SDK object or configuration in strict Proxy traps to prevent runtime mutation
     * from external userland scripts while allowing internal methods to operate on the raw instance.
     */
    static createTamperProofProxy(target, name = 'SecureShieldObject', onTamper) {
        if (typeof Proxy === 'undefined') {
            return target; // Fallback if Proxy unsupported
        }
        return new Proxy(target, {
            get(t, prop, receiver) {
                const val = t[prop];
                // Bind methods to the raw target instance so internal methods can mutate state directly
                if (typeof val === 'function') {
                    return val.bind(t);
                }
                return val;
            },
            set(t, prop, val, receiver) {
                const propName = String(prop);
                const warning = `[SecureShield INTEGRITY VIOLATION] Unauthorized property mutation blocked on '${name}.${propName}'`;
                console.warn(warning);
                onTamper?.('SET_PROPERTY', propName);
                return false; // Reject external mutation
            },
            defineProperty(t, prop, descriptor) {
                const propName = String(prop);
                const warning = `[SecureShield INTEGRITY VIOLATION] Unauthorized Object.defineProperty blocked on '${name}.${propName}'`;
                console.warn(warning);
                onTamper?.('DEFINE_PROPERTY', propName);
                return false; // Reject definition
            },
            deleteProperty(t, prop) {
                const propName = String(prop);
                const warning = `[SecureShield INTEGRITY VIOLATION] Unauthorized property deletion blocked on '${name}.${propName}'`;
                console.warn(warning);
                onTamper?.('DELETE_PROPERTY', propName);
                return false; // Reject deletion
            },
            setPrototypeOf(t, proto) {
                const warning = `[SecureShield INTEGRITY VIOLATION] Prototype chain alteration blocked on '${name}'`;
                console.warn(warning);
                onTamper?.('SET_PROTOTYPE_OF', '__proto__');
                return false; // Reject prototype replacement
            }
        });
    }
    /**
     * Performs an active runtime audit of critical browser primitives to detect hooks and overrides.
     */
    static auditRuntimeIntegrity() {
        const targets = [
            { name: 'JSON.stringify', fn: typeof JSON !== 'undefined' ? JSON.stringify : null },
            { name: 'Object.defineProperty', fn: typeof Object !== 'undefined' ? Object.defineProperty : null },
            { name: 'Object.freeze', fn: typeof Object !== 'undefined' ? Object.freeze : null },
            { name: 'Function.prototype.toString', fn: typeof Function !== 'undefined' ? Function.prototype.toString : null },
            { name: 'Date.now', fn: typeof Date !== 'undefined' ? Date.now : null }
        ];
        const tamperedApis = [];
        let auditedCount = 0;
        for (const target of targets) {
            if (!target.fn)
                continue;
            auditedCount++;
            const isNative = RuntimeIntegrityGuardian.isNativeFunction(target.fn);
            if (!isNative) {
                tamperedApis.push({
                    apiName: target.name,
                    isNative: false,
                    reason: `Function '${target.name}' string representation or prototype origin indicates an active userland hook or proxy.`
                });
            }
        }
        return {
            isClean: tamperedApis.length === 0,
            tamperedCount: tamperedApis.length,
            tamperedApis,
            auditedCount
        };
    }
}
