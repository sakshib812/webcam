export class AdblockerPresenceDetector {
    static scan() {
        const startTime = performance.now();
        let triggered = false;
        const evidence = {};
        try {
            if (typeof document !== 'undefined') {
                const bait = document.createElement('div');
                bait.className = 'adsbox google-ad ad-banner pub_300x250';
                bait.style.position = 'absolute';
                bait.style.top = '-9999px';
                bait.style.left = '-9999px';
                bait.style.width = '1px';
                bait.style.height = '1px';
                document.body?.appendChild(bait);
                if (bait.offsetParent === null || bait.offsetHeight === 0) {
                    evidence['adblocker_active'] = 'true';
                }
                else {
                    evidence['adblocker_active'] = 'false';
                }
                bait.remove();
            }
        }
        catch {
            evidence['error'] = 'eval_failed';
        }
        return {
            id: 'adblocker_presence_detector',
            name: 'Ad-Blocker & Content Blocker Decoy Element Detector',
            triggered: false, // Weak contextual feature: never fails/triggers as standalone penalty
            severity: 1,
            category: 'ENVIRONMENT',
            event: 'ADBLOCKER_DETECTED',
            confidence: 0.50,
            fpRiskTier: 'HIGH',
            evasionDifficulty: 'LOW',
            requiresConsent: false,
            implementationCost: 'LOW',
            status: 'PASSED',
            executionTimeMs: Math.round(performance.now() - startTime),
            evidence
        };
    }
}
