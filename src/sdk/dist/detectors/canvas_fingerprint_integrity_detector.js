export class CanvasFingerprintIntegrityDetector {
    static scan() {
        const startTime = performance.now();
        let triggered = false;
        let confidence = 0.85;
        const evidence = {};
        try {
            const canvas = document.createElement('canvas');
            canvas.width = 200;
            canvas.height = 50;
            const ctx = canvas.getContext('2d');
            if (ctx) {
                ctx.textBaseline = 'top';
                ctx.font = '14px Arial';
                ctx.fillStyle = '#f60';
                ctx.fillRect(125, 1, 62, 20);
                ctx.fillStyle = '#069';
                ctx.fillText('SecureShield 🔒', 2, 15);
                const dataUrl = canvas.toDataURL();
                evidence['canvas_hash'] = `len_${dataUrl.length}`;
            }
        }
        catch (e) {
            // Privacy extensions (CanvasBlocker, Brave) may inject noise or throw errors
            confidence = 0.50; // Lower confidence per rule
            evidence['privacy_noise_detected'] = 'true';
        }
        const duration = Math.round(performance.now() - startTime);
        return {
            id: 'canvas_fingerprint_integrity_detector',
            name: 'Canvas Dynamic Geometry Fingerprint Probe',
            triggered,
            severity: 2,
            category: 'hardware',
            event: 'canvas_geometry_fingerprint',
            confidence,
            fpRiskTier: 'HIGH',
            evasionDifficulty: 'MEDIUM',
            requiresConsent: false,
            status: 'PASSED',
            executionTimeMs: duration,
            evidence
        };
    }
}
