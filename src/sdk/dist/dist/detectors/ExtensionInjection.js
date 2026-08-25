export class ExtensionInjectionDetector {
    static scan() {
        let triggered = false;
        const evidence = {};
        try {
            const scripts = Array.from(document.querySelectorAll('script'));
            for (const script of scripts) {
                if (script.src && (script.src.startsWith('chrome-extension://') || script.src.startsWith('moz-extension://'))) {
                    triggered = true;
                    evidence['extension_script'] = script.src;
                    break;
                }
            }
        }
        catch (e) {
            evidence['error'] = e.message;
        }
        return {
            id: 'extension_injection_detector',
            triggered,
            severity: 3, // HIGH
            category: 'code',
            event: 'browser_extension_script_injected',
            evidence
        };
    }
}
