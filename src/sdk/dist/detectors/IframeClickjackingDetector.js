export class IframeClickjackingDetector {
    static scan() {
        let triggered = false;
        const evidence = {};
        try {
            if (window.self !== window.top) {
                triggered = true;
                evidence['framed'] = 'true';
                try {
                    evidence['top_origin'] = window.top?.location.href || 'cross-origin';
                }
                catch (e) {
                    evidence['top_origin'] = 'cross-origin-restricted';
                }
            }
        }
        catch (e) {
            triggered = true;
            evidence['error'] = e.message;
        }
        return {
            id: 'iframe_clickjacking_detector',
            triggered,
            severity: 3, // HIGH
            category: 'ui',
            event: 'iframe_clickjacking_framing_detected',
            evidence
        };
    }
}
