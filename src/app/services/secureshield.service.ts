// src/app/services/secureshield.service.ts
import { Injectable, signal } from '@angular/core';
import { SecureShield, SecurityAuditReport } from '@secureshield/web';

@Injectable({
    providedIn: 'root'
})
export class SecureShieldService {
    private sdkInstance: any = null;
    public isShieldActive = signal<boolean>(false);
    public lastReport = signal<(SecurityAuditReport & { trustScore?: number }) | null>(null);

    async initSecureShield(): Promise<SecurityAuditReport | null> {
        try {
            this.sdkInstance = await SecureShield.init({
                headerKey: 'enc:v1:bf004452ea9f2170fa2f0d75:b0d33433ad98d9648c17bafe4a45cdde:07ff537a3441f0059e1134d902233f',
                encryptionKey: 'U1MEOYmR2f9ZePypUKvFtCGC7xHuXcJKsukRKEeHjYQ=',
                initializationKey: 'INIT_utgGBnB1MH-yIQdgANZ0ZgYZWiBb3F-N',
                tenantId: 'TEN-SAKSHI-8743',
                appId: 'ast_web_285900',
                serverUrl: 'https://radiator-waving-cahoots.ngrok-free.dev/api/v1/telemetry/ingest',
                environment: 'staging',
                skipHandshake: true,
                enableRuntimeIntegrityWatchdog: true,
                enablePrototypeFreezing: false,        // ✅ Angular Signals & Hydration compatibility
                enableStorageLeakScrubber: true,

                onTamperDetected: (apiName: string, reason?: string) => {
                    console.warn(`[SecureShield Tamper Alert] ${apiName}: ${reason}`);
                },
                onRemediationTriggered: (action: string, reason?: string) => {
                    console.warn(`[SecureShield Policy Action] ${action} — ${reason || 'Triggered'}`);
                }
            } as any);

            const report = await this.sdkInstance.evaluateSecurityState();
            this.lastReport.set(report);
            this.isShieldActive.set(true);
            return report;
        } catch (error) {
            console.error('[SecureShield] Init failed:', error);
            return null;
        }
    }

    isCleanForTransaction(): boolean {
        if (!this.sdkInstance) return false;
        const audit = this.sdkInstance.runScan();
        return audit.verdict === 'SECURE' && (audit.risk_score || 0) < 50;
    }
}