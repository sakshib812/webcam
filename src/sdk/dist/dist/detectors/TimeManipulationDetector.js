// Module initialization time anchors
const INIT_DATE_NOW = Date.now();
const INIT_PERF_NOW = typeof performance !== 'undefined' && performance.now ? performance.now() : 0;
export class TimeManipulationDetector {
    static serverAnchorTimeMs = null;
    static serverAnchorPerfMs = null;
    /**
     * Anchors a trusted server timestamp (e.g. from backend attestation or policy response)
     */
    static setServerTimeAnchor(serverTimestampMs) {
        TimeManipulationDetector.serverAnchorTimeMs = serverTimestampMs;
        TimeManipulationDetector.serverAnchorPerfMs = typeof performance !== 'undefined' && performance.now ? performance.now() : 0;
    }
    static scan(options) {
        const nowMs = Date.now().toString();
        const maxDriftMs = options?.maxAllowedDriftMs ?? (5 * 60 * 1000); // 5 minutes default
        const evidence = {
            scan_timestamp_ms: nowMs,
            probe_target: 'Wall-Clock Date.now() vs Monotonic performance.now() & Server NTP Anchor',
            probe_technique: 'monotonic_time_delta_drift_audit',
            max_allowed_drift_ms: maxDriftMs
        };
        let triggered = false;
        const anomalies = [];
        const currentDateNow = Date.now();
        const currentPerfNow = typeof performance !== 'undefined' && performance.now ? performance.now() : 0;
        try {
            // 1. Sanity Check: Retroactive or extreme future date check
            // Earliest valid date: Jan 1, 2024 (1704067200000); Max reasonable future: year 2038
            if (currentDateNow < 1704067200000) {
                triggered = true;
                anomalies.push(`Retroactive wall clock detected: timestamp ${currentDateNow} is prior to year 2024`);
            }
            if (currentDateNow > 2147483647000) {
                triggered = true;
                anomalies.push(`Excessive future wall clock detected: timestamp ${currentDateNow} exceeds year 2038`);
            }
            // 2. Monotonic Drift Verification against module load anchor
            if (INIT_PERF_NOW > 0 && currentPerfNow > 0) {
                const elapsedWallClockMs = currentDateNow - INIT_DATE_NOW;
                const elapsedMonotonicMs = currentPerfNow - INIT_PERF_NOW;
                const driftDeltaMs = Math.abs(elapsedWallClockMs - elapsedMonotonicMs);
                evidence['session_elapsed_wall_clock_ms'] = elapsedWallClockMs;
                evidence['session_elapsed_monotonic_ms'] = elapsedMonotonicMs.toFixed(2);
                evidence['session_time_drift_ms'] = driftDeltaMs.toFixed(2);
                // If drift exceeds allowed threshold (e.g. user modified OS clock while app is running)
                if (driftDeltaMs > maxDriftMs) {
                    triggered = true;
                    anomalies.push(`Client clock jumped/rewound by ${(driftDeltaMs / 1000).toFixed(1)}s during session (threshold: ${(maxDriftMs / 1000)}s)`);
                }
            }
            // 3. Server-Anchored NTP Drift Verification (if server timestamp provided)
            if (TimeManipulationDetector.serverAnchorTimeMs !== null && TimeManipulationDetector.serverAnchorPerfMs !== null && currentPerfNow > 0) {
                const elapsedSinceAnchor = currentPerfNow - TimeManipulationDetector.serverAnchorPerfMs;
                const expectedServerTime = TimeManipulationDetector.serverAnchorTimeMs + elapsedSinceAnchor;
                const serverSkewMs = Math.abs(currentDateNow - expectedServerTime);
                evidence['server_anchor_timestamp_ms'] = TimeManipulationDetector.serverAnchorTimeMs;
                evidence['server_anchored_skew_ms'] = serverSkewMs.toFixed(2);
                if (serverSkewMs > maxDriftMs) {
                    triggered = true;
                    anomalies.push(`Client clock skewed from server time by ${(serverSkewMs / 1000).toFixed(1)}s (threshold: ${(maxDriftMs / 1000)}s)`);
                }
            }
            evidence['time_anomalies'] = anomalies;
            evidence['actual_value'] = triggered
                ? `System time manipulation or severe clock skew detected: ${anomalies.join('; ')}`
                : 'Wall-clock and monotonic execution timers synchronized within acceptable drift tolerance';
            evidence['expected_value'] = 'Client system clock must match monotonic progress within 5 minutes tolerance';
            evidence['threat_classification'] = triggered
                ? 'SYSTEM_CLOCK_TAMPERING_OR_REPLAY_RISK'
                : 'Synchronized client time environment';
            evidence['remediation_guidance'] = triggered
                ? 'Verify client system clock synchronization with network time (NTP) to prevent session token validation errors'
                : 'No action required. System clock synchronized.';
        }
        catch (e) {
            evidence['error'] = `TimeManipulationDetector error: ${e.message}`;
        }
        return {
            id: 'time_manipulation_detector',
            triggered,
            severity: triggered ? 2 : 0, // P2 Medium severity risk signal
            category: 'environment',
            event: triggered ? 'web_time_skew_detected' : 'web_time_skew_verified_clean',
            confidence: 0.85,
            fpRiskTier: 'LOW',
            evasionDifficulty: 'MEDIUM',
            status: triggered ? 'FAILED' : 'PASSED',
            name: 'Time Manipulation Detector',
            evidence
        };
    }
}
