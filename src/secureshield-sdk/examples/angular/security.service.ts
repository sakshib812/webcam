import { Injectable } from '@angular/core';
import { SecureShield, SecurityAuditReport } from '@secureshield/web';

@Injectable({
  providedIn: 'root'
})
export class SecurityService {
  private sdkInstance: any = null;

  async initSecurity(): Promise<SecurityAuditReport | null> {
    try {
      this.sdkInstance = await SecureShield.init({
        tenantId: 'TEN-CLIENT-PROD',
        appId: 'angular_client_app',
        serverUrl: 'https://radiator-waving-cahoots.ngrok-free.dev/api/v1/telemetry/ingest',
        enableStorageLeakScrubber: true,
        enableRuntimeIntegrityWatchdog: true
      });

      const report = await this.sdkInstance.evaluateSecurityState();
      return report;
    } catch (error) {
      console.error('SecureShield initialization failed in Angular:', error);
      return null;
    }
  }

  async runScan(): Promise<SecurityAuditReport | null> {
    if (!this.sdkInstance) {
      return this.initSecurity();
    }
    return this.sdkInstance.evaluateSecurityState();
  }
}
