import React, { useEffect, useState, createContext, useContext } from 'react';
import { SecureShield, SecurityAuditReport } from '@secureshield/web';

interface SecurityContextType {
  isSecure: boolean;
  trustScore: number;
  report: SecurityAuditReport | null;
  refreshScan: () => Promise<void>;
}

const SecurityContext = createContext<SecurityContextType>({
  isSecure: false,
  trustScore: 100,
  report: null,
  refreshScan: async () => {}
});

export const useSecurity = () => useContext(SecurityContext);

export function SecureShieldProvider({ children }: { children: React.ReactNode }) {
  const [report, setReport] = useState<SecurityAuditReport | null>(null);
  const [isSecure, setIsSecure] = useState<boolean>(true);
  const [trustScore, setTrustScore] = useState<number>(100);
  const [sdkInstance, setSdkInstance] = useState<any>(null);

  const performScan = async (instance?: any) => {
    const activeSdk = instance || sdkInstance;
    if (!activeSdk) return;

    try {
      const auditReport = await activeSdk.evaluateSecurityState();
      setReport(auditReport);
      setTrustScore(auditReport.trustScore || Math.max(0, 100 - auditReport.risk_score));
      setIsSecure(auditReport.verdict === 'SECURE');
    } catch (err) {
      console.error('[SecureShield] Scan error:', err);
    }
  };

  useEffect(() => {
    async function initSdk() {
      try {
        const sdk = await SecureShield.init({
          tenantId: 'TEN-CLIENT-PROD',
          appId: 'client_react_portal',
          serverUrl: 'https://radiator-waving-cahoots.ngrok-free.dev/api/v1/telemetry/ingest',
          enableStorageLeakScrubber: true,
          enableRuntimeIntegrityWatchdog: true,
          enableTabBlurShield: false,
          onRemediationTriggered: (action, reason) => {
            console.warn(`[SecureShield Remote Action]: ${action} (${reason || 'Threat policy enforced'})`);
          }
        });

        setSdkInstance(sdk);
        await performScan(sdk);
      } catch (err) {
        console.error('[SecureShield] Initialization failed:', err);
      }
    }

    initSdk();
  }, []);

  return (
    <SecurityContext.Provider value={{ isSecure, trustScore, report, refreshScan: performScan }}>
      {children}
    </SecurityContext.Provider>
  );
}
