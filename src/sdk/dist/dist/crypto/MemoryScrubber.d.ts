/**
 * MemoryScrubber: Best-Effort TypedArray & Buffer Memory Zeroing Engine
 *
 * Web equivalent of native C/C++ memset_s / explicit_bzero.
 * While JavaScript strings are immutable and garbage-collected, binary memory
 * represented by TypedArrays (Uint8Array, ArrayBuffer, DataView) can and must be explicitly
 * sanitized to reduce plaintext credential exposure in heap snapshots and memory dumps.
 */
export declare class MemoryScrubber {
    /**
     * Performs a multi-pass cryptographic overwrite and zeroing on any TypedArray or ArrayBuffer.
     */
    static zero(target: ArrayBufferView | ArrayBuffer | null | undefined): void;
    /**
     * Recursively traverses an object or array and wipes all contained TypedArrays / ArrayBuffers.
     */
    static scrubObject(obj: any, maxDepth?: number): void;
}
/**
 * SecureMemoryBuffer: RAII-style scoped memory wrapper that guarantees
 * automatic buffer scrubbing upon scope exit (even during errors).
 */
export declare class SecureMemoryBuffer {
    /**
     * Allocates or wraps a buffer, executes the provided consumer closure,
     * and guarantees that the buffer is completely zeroed upon exit.
     */
    static use<R>(buffer: Uint8Array | ArrayBuffer, action: (buf: Uint8Array) => R | Promise<R>): Promise<R>;
}
