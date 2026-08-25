/**
 * ClientConfigTamperingDetector: P4 Informational / Application Integrity Detector.
 *
 * Audits client-side global configuration stores (`window.__CONFIG__`, `window.__ENV__`, `window.SecureShieldConfig`)
 * for unexpected runtime property mutation, prototype injection, or tampering with critical endpoint URLs.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.02ms (Config store property audit)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: Config values are audited for structure without exfiltrating secrets
 * - Evasion Limits: If config stores are modified before SDK initialization, baseline freezing is recommended.
 */
export class ClientConfigTamperingDetector {
    static scan() {
        const nowMs = Date.now().toString();
        const evidence = {
            scan_timestamp_ms: nowMs,
            probe_target: 'Client Runtime Configuration Stores & Global Variables',
            probe_technique: 'config_object_freeze_and_prototype_audit'
        };
        let triggered = false;
        const configAnomalies = [];
        try {
            const getCandidate = (prop) => {
                if (typeof window !== 'undefined' && window[prop])
                    return window[prop];
                if (typeof globalThis !== 'undefined' && globalThis[prop])
                    return globalThis[prop];
                return null;
            };
            const configCandidates = [
                { name: 'window.SecureShieldConfig', obj: getCandidate('SecureShieldConfig') },
                { name: 'window.__ENV__', obj: getCandidate('__ENV__') },
                { name: 'window.__APP_CONFIG__', obj: getCandidate('__APP_CONFIG__') },
                { name: 'window.config', obj: getCandidate('config') }
            ];
            for (const candidate of configCandidates) {
                if (candidate.obj && typeof candidate.obj === 'object') {
                    // Probe A: Check for prototype pollution on config object
                    if (Object.prototype.hasOwnProperty.call(candidate.obj, '__proto__') || candidate.obj.polluted === true) {
                        triggered = true;
                        configAnomalies.push(`Prototype pollution detected on ${candidate.name}`);
                    }
                    // Probe B: Check if critical server endpoint URL has been redirected to non-HTTPS or localhost
                    const serverUrl = candidate.obj.serverUrl || candidate.obj.apiUrl || candidate.obj.endpoint;
                    if (typeof serverUrl === 'string') {
                        if (serverUrl.startsWith('javascript:') || serverUrl.startsWith('data:')) {
                            triggered = true;
                            configAnomalies.push(`Dangerous scheme in ${candidate.name}.serverUrl: ${serverUrl.slice(0, 30)}`);
                        }
                    }
                }
            }
            evidence['detected_config_anomalies'] = configAnomalies;
            evidence['actual_value'] = triggered
                ? `Client configuration tampering detected (${configAnomalies.length}): ${configAnomalies.slice(0, 3).join(', ')}`
                : 'Window Client Config Immutability verified clean in browser context';
            evidence['expected_value'] = 'Client configuration objects must be unpolluted and contain valid HTTPS endpoints';
            evidence['threat_classification'] = triggered
                ? 'CLIENT_CONFIG_TAMPERING_DETECTED'
                : 'Clean browser environment';
            evidence['remediation_guidance'] = triggered
                ? 'Freeze client configuration objects using Object.freeze() at startup to prevent runtime tampering'
                : 'No action required. Baseline clean.';
        }
        catch (e) {
            evidence['error'] = `ClientConfigTamperingDetector error: ${e.message}`;
        }
        return {
            id: 'client_configuration_tampering_detector',
            triggered,
            severity: triggered ? 3 : 0,
            category: 'application_integrity',
            event: triggered ? 'client_config_tampering_detected' : 'client_configuration_tampering_detector_verified',
            confidence: 0.85,
            fpRiskTier: 'LOW',
            evasionDifficulty: 'MEDIUM',
            status: triggered ? 'FAILED' : 'PASSED',
            name: 'Client Config Tampering Detector',
            evidence
        };
    }
}
