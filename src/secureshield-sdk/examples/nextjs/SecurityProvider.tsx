'use client';

import { useEffect } from 'react';
import { SecureShield } from '@secureshield/web';

export function SecurityProvider({ children }: { children: React.ReactNode }) {
  useEffect(() => {
    if (typeof window !== 'undefined') {
      SecureShield.init({
        tenantId: 'TEN-CLIENT-PROD',
        appId: 'nextjs_client_app',
        serverUrl: 'https://radiator-waving-cahoots.ngrok-free.dev/api/v1/telemetry/ingest',
        enableStorageLeakScrubber: true,
        enableRuntimeIntegrityWatchdog: true
      }).then(sdk => {
        return sdk.evaluateSecurityState();
      }).then(report => {
        console.log(`[Next.js SecureShield] Posture: ${report.verdict} (Score: ${report.trustScore}/100)`);
      }).catch(err => {
        console.error('[Next.js SecureShield] Init Error:', err);
      });
    }
  }, []);

  return <>{children}</>;
}
