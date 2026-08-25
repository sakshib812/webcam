export class ClientHintsConsistencyDetector {
    static scan() {
        const startTime = performance.now();
        let triggered = false;
        const evidence = {};
        try {
            const nav = navigator;
            if (nav.userAgentData) {
                evidence['user_agent_data_supported'] = 'true';
                evidence['mobile'] = String(nav.userAgentData.mobile);
                evidence['brands'] = nav.userAgentData.brands ? nav.userAgentData.brands.map((b) => `${b.brand}/${b.version}`).join(', ') : 'none';
                // Check consistency: if userAgent claims iPhone/Android but mobile flag is false
                const ua = nav.userAgent || '';
                const claimsMobileUA = /Android|iPhone|iPad|iPod/i.test(ua);
                if (claimsMobileUA && !nav.userAgentData.mobile) {
                    triggered = true;
                    evidence['ua_client_hints_mismatch'] = 'claimed_mobile_ua_but_desktop_hints';
                }
            }
            else {
                evidence['user_agent_data_supported'] = 'false';
            }
        }
        catch {
            evidence['error'] = 'eval_failed';
        }
        return {
            id: 'client_hints_consistency_detector',
            name: 'Client Hints vs User-Agent Consistency Detector',
            triggered,
            severity: 3,
            category: 'SPOOFING',
            event: 'CLIENT_HINTS_MISMATCH',
            confidence: 0.90,
            fpRiskTier: 'LOW',
            evasionDifficulty: 'MEDIUM',
            requiresConsent: false,
            implementationCost: 'LOW',
            status: triggered ? 'FAILED' : 'PASSED',
            executionTimeMs: Math.round(performance.now() - startTime),
            evidence
        };
    }
}
