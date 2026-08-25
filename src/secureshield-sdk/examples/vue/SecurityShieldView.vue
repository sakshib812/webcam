<template>
  <div class="security-card">
    <h2>SecureShield Device Trust Monitor</h2>
    <div class="metrics-group">
      <span class="badge" :class="verdict === 'SECURE' ? 'badge-secure' : 'badge-blocked'">
        {{ verdict || 'EVALUATING' }}
      </span>
      <span class="score">Trust Score: {{ trustScore }}/100</span>
    </div>
    <button @click="refreshScan" class="scan-btn">Trigger Live Ingest</button>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { SecureShield } from '@secureshield/web';

const verdict = ref('');
const trustScore = ref(100);
let sdkInstance: any = null;

const refreshScan = async () => {
  if (!sdkInstance) return;
  const report = await sdkInstance.evaluateSecurityState();
  verdict.value = report.verdict;
  trustScore.value = report.trustScore;
};

onMounted(async () => {
  try {
    sdkInstance = await SecureShield.init({
      tenantId: 'TEN-CLIENT-PROD',
      appId: 'vue_client_portal',
      serverUrl: 'https://radiator-waving-cahoots.ngrok-free.dev/api/v1/telemetry/ingest',
      enableStorageLeakScrubber: true,
      enableRuntimeIntegrityWatchdog: true
    });

    await refreshScan();
  } catch (err) {
    console.error('SecureShield Vue error:', err);
  }
});
</script>

<style scoped>
.security-card {
  padding: 1.5rem;
  background: #111827;
  color: #fff;
  border-radius: 12px;
  font-family: sans-serif;
}
.metrics-group { display: flex; gap: 1rem; align-items: center; margin: 1rem 0; }
.badge { padding: 4px 12px; border-radius: 6px; font-weight: bold; }
.badge-secure { background: rgba(16, 185, 129, 0.2); color: #10b981; }
.badge-blocked { background: rgba(239, 68, 68, 0.2); color: #ef4444; }
.scan-btn { background: #2563eb; color: #fff; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; }
</style>
