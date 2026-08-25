export class ConsoleTamperingDetector {
    static scan() {
        let triggered = false;
        const evidence = {};
        try {
            const nativeLogStr = Function.prototype.toString.call(console.log);
            if (!nativeLogStr.includes('[native code]')) {
                triggered = true;
                evidence['console_override'] = nativeLogStr;
            }
        }
        catch (e) {
            triggered = true;
            evidence['error'] = e.message;
        }
        return {
            id: 'console_tampering_detector',
            triggered,
            severity: 3, // HIGH
            category: 'code',
            event: 'console_object_tampered',
            evidence
        };
    }
}
