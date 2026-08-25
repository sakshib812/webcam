export class GlobalPrivacyControlDetector {
    static scan() {
        const startTime = performance.now();
        let triggered = false;
        const evidence = {};
        try {
            const nav = navigator;
            const gpc = nav.globalPrivacyControl;
            const dnt = nav.doNotTrack || window.doNotTrack;
            evidence['global_privacy_control'] = gpc !== undefined ? String(gpc) : 'not_set';
            evidence['do_not_track'] = dnt !== undefined ? String(dnt) : 'not_set';
            if (gpc === true || dnt === '1' || dnt === 'yes') {
                evidence['privacy_preference_enforced'] = 'true';
            }
            else {
                evidence['privacy_preference_enforced'] = 'false';
            }
        }
        catch {
            evidence['error'] = 'eval_failed';
        }
        return {
            id: 'global_privacy_control_detector',
            name: 'Do Not Track & Global Privacy Control Compliance Signal',
            triggered: false, // Compliance input, not a threat detector failure
            severity: 0,
            category: 'COMPLIANCE',
            event: 'GPC_SIGNAL_READ',
            confidence: 1.0,
            fpRiskTier: 'LOW',
            evasionDifficulty: 'LOW',
            requiresConsent: false,
            implementationCost: 'LOW',
            status: 'PASSED',
            executionTimeMs: Math.round(performance.now() - startTime),
            evidence
        };
    }
}
