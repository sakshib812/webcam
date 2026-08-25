export class DevToolsDetector {
    static scan() {
        let triggered = false;
        const evidence = {};
        // Probe 1: Check window outer vs inner dimension delta
        const threshold = 160;
        const widthDiff = window.outerWidth - window.innerWidth;
        const heightDiff = window.outerHeight - window.innerHeight;
        if (widthDiff > threshold || heightDiff > threshold) {
            triggered = true;
            evidence['window_delta'] = `widthDiff:${widthDiff}, heightDiff:${heightDiff}`;
        }
        // Probe 2: Firebug / console element inspection trap
        const element = new Image();
        Object.defineProperty(element, 'id', {
            get: function () {
                triggered = true;
                evidence['console_getter_trap'] = 'active';
                return 'devtools';
            }
        });
        return {
            id: 'browser_devtools_detector',
            triggered,
            severity: 3, // HIGH
            category: 'environment',
            event: 'browser_devtools_open',
            evidence
        };
    }
}
