# SecureShield Web SDK — Client Integration Guide

> **Version**: 1.0.0  
> **Production Telemetry Ingest Endpoint**: `https://radiator-waving-cahoots.ngrok-free.dev/api/v1/telemetry/ingest`  
> **Target Platforms**: React, Next.js, Vue 3, Angular, Vanilla JavaScript, Node.js

---

## 📦 1. Quick Start Installation

You can install the **SecureShield Web SDK** using either of the following methods:

### Method A: Install via Local NPM Package Archive (`.tgz`)
Copy `secureshield-web-1.0.0.tgz` from the `sdk/` folder into your project root and run:
```bash
# Using NPM
npm install ./sdk/secureshield-web-1.0.0.tgz

# Using Yarn
yarn add file:./sdk/secureshield-web-1.0.0.tgz

# Using PNPM
pnpm add ./sdk/secureshield-web-1.0.0.tgz
```

### Method B: Direct Script Tag (Vanilla HTML / CDN)
Include the standalone bundle `secureshield-web.global.js` in your HTML `<head>` or `<body>`:
```html
<script src="sdk/secureshield-web.global.js"></script>
```

---

## ⚡ 2. Pre-Configured Live Ingestion Endpoint

Your dedicated ingestion gateway is pre-configured at:
```text
https://radiator-waving-cahoots.ngrok-free.dev/api/v1/telemetry/ingest
```

When client scans run, telemetry audits across **60+ runtime detectors** are automatically evaluated and securely transmitted to your backend risk engine for live policy verification.

---

## ⚛️ 3. React / Next.js Integration

### React 18+ Application (`src/App.tsx` or `src/components/SecureShieldProvider.tsx`)
```tsx
import React, { useEffect, useState } from 'react';
import { SecureShield, SecurityAuditReport } from '@secureshield/web';

export function SecureShieldProvider({ children }: { children: React.ReactNode }) {
  const [isInitialized, setIsInitialized] = useState(false);
  const [report, setReport] = useState<SecurityAuditReport | null>(null);

  useEffect(() => {
    async function initSecurity() {
      try {
        const sdk = await SecureShield.init({
          tenantId: 'TEN-CLIENT-PROD',
          appId: 'client_enterprise_portal',
          serverUrl: 'https://radiator-waving-cahoots.ngrok-free.dev/api/v1/telemetry/ingest',
          skipHandshake: true, // Set to true to ingest telemetry directly without auth handshake
          enableStorageLeakScrubber: true,
          enableRuntimeIntegrityWatchdog: true,
          enableTabBlurShield: false, // Set to true to blur screen on tab defocus
          onRemediationTriggered: (action, reason) => {
            console.warn(`[SecureShield Policy Action]: ${action} — ${reason}`);
          }
        });

        // Run full baseline scan and ingest telemetry
        const initialReport = await sdk.evaluateSecurityState();
        setReport(initialReport);
        setIsInitialized(true);

        console.log(`[SecureShield] Security Verdict: ${initialReport.verdict} (Trust: ${initialReport.trustScore}/100)`);
      } catch (err) {
        console.error('[SecureShield] Failed to initialize Web SDK:', err);
      }
    }

    initSecurity();
  }, []);

  return <>{children}</>;
}
```

### Next.js App Router (`src/app/providers.tsx`)
```tsx
'use client';

import { useEffect } from 'react';
import { SecureShield } from '@secureshield/web';

export function SecurityProvider({ children }: { children: React.ReactNode }) {
  useEffect(() => {
    if (typeof window !== 'undefined') {
      SecureShield.init({
        tenantId: 'TEN-CLIENT-PROD',
        appId: 'nextjs_client_portal',
        serverUrl: 'https://radiator-waving-cahoots.ngrok-free.dev/api/v1/telemetry/ingest',
        enableStorageLeakScrubber: true,
        enableRuntimeIntegrityWatchdog: true
      });
    }
  }, []);

  return <>{children}</>;
}
```

---

## 🟢 4. Vue 3 (Composition API)

```vue
<template>
  <div class="app-layout">
    <div v-if="securityVerdict" class="security-badge" :class="securityVerdict.toLowerCase()">
      Security Status: {{ securityVerdict }} (Trust Score: {{ trustScore }}/100)
    </div>
    <slot />
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { SecureShield } from '@secureshield/web';

const trustScore = ref(100);
const securityVerdict = ref('');

onMounted(async () => {
  try {
    const sdk = await SecureShield.init({
      tenantId: 'TEN-CLIENT-PROD',
      appId: 'vue_client_app',
      serverUrl: 'https://radiator-waving-cahoots.ngrok-free.dev/api/v1/telemetry/ingest',
      enableStorageLeakScrubber: true,
      enableRuntimeIntegrityWatchdog: true
    });

    const report = await sdk.evaluateSecurityState();
    trustScore.value = report.trustScore;
    securityVerdict.value = report.verdict;
  } catch (e) {
    console.error('SecureShield error:', e);
  }
});
</script>
```

---

## 🌐 5. Vanilla HTML / JavaScript

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Client Web Application</title>
  <script src="sdk/secureshield-web.global.js"></script>
</head>
<body>
  <h1>Protected Client Portal</h1>
  <p id="sec-status">Initializing security engine...</p>

  <script>
    async function setupSecurity() {
      const SecureShield = window.SecureShieldWeb.SecureShield;

      const sdk = await SecureShield.init({
        tenantId: 'TEN-CLIENT-PROD',
        appId: 'vanilla_web_portal',
        serverUrl: 'https://radiator-waving-cahoots.ngrok-free.dev/api/v1/telemetry/ingest',
        enableStorageLeakScrubber: true
      });

      const report = await sdk.evaluateSecurityState();
      document.getElementById('sec-status').textContent =
        `Security Verdict: ${report.verdict} (Score: ${report.trustScore}/100)`;
    }

    setupSecurity();
  </script>
</body>
</html>
```

---

## 🛡️ 6. Detection Capabilities Included

| Category | Detectors Included | Description |
|---|---|---|
| **Runtime Integrity** | Prototype pollution, Native API hook detection, Console tampering, Dynamic eval probes | Detects script injection, malicious extensions, and DOM tampering. |
| **Browser Fingerprint** | Canvas, WebGL, WebGPU, Screen Geometry, Hardware Topology, Font Enumeration | Identifies virtual environments, automated bots, and anti-detect browsers. |
| **Automation Defense** | Headless Chrome, Puppeteer, Selenium, WebDriver flags | Detects automated scrapers, credential stuffers, and headless runners. |
| **Data Leak Prevention** | Storage Leak Scrubber, Session storage token scrubber | Purges unencrypted JWTs, private keys, or tokens accidentally exposed in `localStorage`. |
| **UI Shielding** | Tab blur shield, Watermark overlay, Secure clipboard timeout | Mitigates visual snooping and clipboard hijacking attacks. |

---

## 🧪 7. 5-Second Instant Verification

To test immediately without coding:
1. Double-click `quick-test.html` in your browser.
2. Click **"Run Security Scan & Ingest"**.
3. Check the HTTP 200 OK response received from the backend ingestion gateway.
