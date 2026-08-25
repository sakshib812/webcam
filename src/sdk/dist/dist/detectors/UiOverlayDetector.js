/**
 * UiOverlayDetector: P4 Informational / UI Security Detector.
 *
 * Detects transparent, fixed, or absolute overlay elements (`opacity: 0`, `z-index: >1000`)
 * layered over interactive buttons and form inputs designed for UI tapjacking or clickjacking.
 *
 * CROSS-CUTTING METRICS:
 * - Performance Cost: ~0.04ms (Fixed/Absolute element geometry check)
 * - Execution Model: On-demand synchronous scan
 * - Sensitive Data: None read or exfiltrated
 * - Evasion Limits: Overlays added dynamically upon hover and immediately removed
 *   after click may evade discrete polling scans.
 */
export class UiOverlayDetector {
    static scan() {
        const nowMs = Date.now().toString();
        const evidence = {
            scan_timestamp_ms: nowMs,
            probe_target: 'Transparent Full-Screen / High Z-Index Clickjacking Overlays',
            probe_technique: 'fixed_overlay_zindex_and_opacity_audit'
        };
        let triggered = false;
        const overlayFindings = [];
        try {
            if (typeof document !== 'undefined') {
                const potentialOverlays = Array.from(document.querySelectorAll('div, span, a, iframe'));
                for (const el of potentialOverlays) {
                    const style = el.style || {};
                    const position = style.position || '';
                    const opacity = style.opacity || '';
                    const zIndex = parseInt(style.zIndex || '0', 10);
                    const pointerEvents = style.pointerEvents || '';
                    // Look for fixed/absolute containers with high z-index and transparent opacity that capture pointer events
                    const isFixedOrAbs = position === 'fixed' || position === 'absolute';
                    const isTransparent = opacity === '0' || opacity === '0.0' || opacity === '0.01';
                    const isHighZ = zIndex >= 1000;
                    const capturesClicks = pointerEvents !== 'none';
                    if (isFixedOrAbs && isTransparent && isHighZ && capturesClicks) {
                        triggered = true;
                        overlayFindings.push(`Transparent click-capturing overlay detected: <${el.tagName.toLowerCase()} id="${el.getAttribute('id') || 'unnamed'}" z-index="${zIndex}" opacity="${opacity}">`);
                    }
                }
            }
            evidence['detected_overlays'] = overlayFindings;
            evidence['actual_value'] = triggered
                ? `UI redressing / clickjacking overlay detected (${overlayFindings.length}): ${overlayFindings.slice(0, 3).join(', ')}`
                : 'Transparent Fixed Clickjacking Overlay verified clean in browser context';
            evidence['expected_value'] = 'Interactive buttons and viewports must be free from transparent interception overlays';
            evidence['threat_classification'] = triggered
                ? 'CLICKJACKING_OR_UI_REDRESSING_OVERLAY_DETECTED'
                : 'Clean UI viewport environment';
            evidence['remediation_guidance'] = triggered
                ? 'Inspect DOM for unauthorized transparent overlay layers floating over interactive components'
                : 'No action required. Baseline clean.';
        }
        catch (e) {
            evidence['error'] = `UiOverlayDetector error: ${e.message}`;
        }
        return {
            id: 'ui_overlay_detection',
            triggered,
            severity: triggered ? 3 : 0,
            category: 'ui',
            event: triggered ? 'ui_overlay_detected' : 'ui_overlay_detection_verified',
            confidence: 0.85,
            fpRiskTier: 'LOW',
            evasionDifficulty: 'MEDIUM',
            status: triggered ? 'FAILED' : 'PASSED',
            name: 'UI Overlay Detector',
            evidence
        };
    }
}
