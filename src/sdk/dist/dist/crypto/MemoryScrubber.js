/**
 * MemoryScrubber: Best-Effort TypedArray & Buffer Memory Zeroing Engine
 *
 * Web equivalent of native C/C++ memset_s / explicit_bzero.
 * While JavaScript strings are immutable and garbage-collected, binary memory
 * represented by TypedArrays (Uint8Array, ArrayBuffer, DataView) can and must be explicitly
 * sanitized to reduce plaintext credential exposure in heap snapshots and memory dumps.
 */
export class MemoryScrubber {
    /**
     * Performs a multi-pass cryptographic overwrite and zeroing on any TypedArray or ArrayBuffer.
     */
    static zero(target) {
        if (!target)
            return;
        try {
            let byteView;
            if (target instanceof ArrayBuffer) {
                byteView = new Uint8Array(target);
            }
            else if (ArrayBuffer.isView(target)) {
                byteView = new Uint8Array(target.buffer, target.byteOffset, target.byteLength);
            }
            else if (target.buffer instanceof ArrayBuffer) {
                byteView = new Uint8Array(target.buffer);
            }
            else {
                return;
            }
            // Pass 1: Cryptographic pseudo-random byte overwrite
            if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
                try {
                    crypto.getRandomValues(byteView);
                }
                catch {
                    // If randomValues fails (e.g. quota limit), proceed to zero fill
                }
            }
            // Pass 2: Definitive zero-byte fill
            byteView.fill(0);
        }
        catch {
            // Best-effort scrubbing: avoid throwing to allow caller flow completion
        }
    }
    /**
     * Recursively traverses an object or array and wipes all contained TypedArrays / ArrayBuffers.
     */
    static scrubObject(obj, maxDepth = 5) {
        if (!obj || typeof obj !== 'object' || maxDepth <= 0) {
            return;
        }
        if (obj instanceof ArrayBuffer || ArrayBuffer.isView(obj)) {
            MemoryScrubber.zero(obj);
            return;
        }
        try {
            if (Array.isArray(obj)) {
                for (const item of obj) {
                    MemoryScrubber.scrubObject(item, maxDepth - 1);
                }
            }
            else {
                for (const key of Object.keys(obj)) {
                    const val = obj[key];
                    if (val instanceof ArrayBuffer || ArrayBuffer.isView(val)) {
                        MemoryScrubber.zero(val);
                    }
                    else if (typeof val === 'object' && val !== null) {
                        MemoryScrubber.scrubObject(val, maxDepth - 1);
                    }
                }
            }
        }
        catch {
            // Suppress traversal error
        }
    }
}
/**
 * SecureMemoryBuffer: RAII-style scoped memory wrapper that guarantees
 * automatic buffer scrubbing upon scope exit (even during errors).
 */
export class SecureMemoryBuffer {
    /**
     * Allocates or wraps a buffer, executes the provided consumer closure,
     * and guarantees that the buffer is completely zeroed upon exit.
     */
    static async use(buffer, action) {
        const view = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
        try {
            return await action(view);
        }
        finally {
            MemoryScrubber.zero(view);
        }
    }
}
