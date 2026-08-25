/**
 * SecureShield Web SDK — Endpoint Ingest Tester
 * Connects the updated Web SDK with a single Ingest API configuration field.
 */

(function () {
  'use strict';

  // State
  let sdkInstance = null;
  let latestAuditReport = null;
  let latestServerResponse = null;
  let autoIngestTimer = null;
  let isAutoIngesting = false;
  let simulatedThreatActive = false;

  // DOM Elements
  const dataIngestApiInput = document.getElementById('dataIngestApiInput');
  const resetEndpointBtn = document.getElementById('resetEndpointBtn');
  const presetChips = document.querySelectorAll('.preset-chip');
  
  const verdictDisplay = document.getElementById('verdictDisplay');
  const verdictSub = document.getElementById('verdictSub');
  const trustScoreDisplay = document.getElementById('trustScoreDisplay');
  const scoreBarFill = document.getElementById('scoreBarFill');
  const detectorsCountDisplay = document.getElementById('detectorsCountDisplay');
  const detectorsPassedCount = document.getElementById('detectorsPassedCount');
  const detectorsFailedCount = document.getElementById('detectorsFailedCount');
  const ingestStatusDisplay = document.getElementById('ingestStatusDisplay');
  const ingestLatencyDisplay = document.getElementById('ingestLatencyDisplay');
  const deviceHashDisplay = document.getElementById('deviceHashDisplay');
  const footerTargetUrl = document.getElementById('footerTargetUrl');

  const runScanAndIngestBtn = document.getElementById('runScanAndIngestBtn');
  const triggerThreatSimBtn = document.getElementById('triggerThreatSimBtn');
  const autoIngestToggleBtn = document.getElementById('autoIngestToggleBtn');
  const autoIngestStatusText = document.getElementById('autoIngestStatusText');
  const refreshPageBtn = document.getElementById('refreshPageBtn');

  const httpStatusChip = document.getElementById('httpStatusChip');
  const respDecisionAction = document.getElementById('respDecisionAction');
  const respLatency = document.getElementById('respLatency');
  const respMessage = document.getElementById('respMessage');

  const tabButtons = document.querySelectorAll('.tab-btn');
  const tabPanes = document.querySelectorAll('.tab-pane');
  const copyTabContentBtn = document.getElementById('copyTabContentBtn');
  const detectorTabBadge = document.getElementById('detectorTabBadge');

  const detectorSearchInput = document.getElementById('detectorSearchInput');
  const filterPills = document.querySelectorAll('.filter-pill');
  const detectorsList = document.getElementById('detectorsList');
  const rawPayloadCode = document.getElementById('rawPayloadCode');
  const rawResponseCode = document.getElementById('rawResponseCode');
  const toastContainer = document.getElementById('toastContainer');

  // Default Ingest API URL
  const DEFAULT_INGEST_URL = 'http://localhost:4000/api/v1/telemetry/ingest';

  // Initialize SDK
  async function initSDK() {
    try {
      const serverUrl = dataIngestApiInput.value.trim() || DEFAULT_INGEST_URL;
      footerTargetUrl.textContent = serverUrl;

      // Access SecureShield from window bundle or module
      const SecureShield = window.SecureShieldWeb ? window.SecureShieldWeb.SecureShield : (window.SecureShield || null);

      if (!SecureShield) {
        throw new Error('SecureShield Web SDK bundle not loaded. Check script tag in index.html');
      }

      sdkInstance = await SecureShield.init({
        tenantId: 'TEN-WEB-TESTER-01',
        appId: 'secureshield_web_tester',
        serverUrl: serverUrl,
        skipHandshake: true,
        enableStorageLeakScrubber: true,
        enableRuntimeIntegrityWatchdog: true,
        enableTabBlurShield: false,
        onRemediationTriggered: (action, reason) => {
          showToast(`Remediation Triggered: ${action} (${reason || 'Threat detected'})`, 'error');
        }
      });

      showToast('SecureShield Web SDK initialized successfully', 'success');
      
      // Perform initial baseline scan & ingest
      await executeScanAndIngest();

    } catch (err) {
      console.error('[SecureShield Tester] Init Error:', err);
      showToast(`Initialization Error: ${err.message}`, 'error');
    }
  }

  // Execute Security Scan & Telemetry Ingestion
  async function executeScanAndIngest() {
    if (!sdkInstance) {
      await initSDK();
      return;
    }

    const ingestUrl = dataIngestApiInput.value.trim() || DEFAULT_INGEST_URL;
    footerTargetUrl.textContent = ingestUrl;

    // Update UI state to Ingesting
    ingestStatusDisplay.textContent = 'TRANSMITTING';
    ingestStatusDisplay.className = 'metric-value text-gradient-cyan';
    ingestLatencyDisplay.textContent = `Connecting to ${new URL(ingestUrl, window.location.href).host}...`;

    const startTime = performance.now();

    try {
      // 1. Run local detection scan
      const report = sdkInstance.runScan();

      // If simulated threat is toggled on, inject a synthetic high-severity threat item
      if (simulatedThreatActive) {
        report.verdict = 'BLOCKED';
        report.risk_score = 92;
        report.risk_tier = 'CRITICAL';
        report.decision_action = 'BLOCK';
        report.failed += 2;
        report.passed -= 2;
        report.items.unshift({
          id: 'simulated_prototype_pollution_hook',
          name: 'Prototype Chain Hooking & Runtime Tampering',
          triggered: true,
          severity: 90,
          category: 'RUNTIME_INTEGRITY',
          event: 'MALICIOUS_PROTOTYPE_HOOK',
          confidence: 0.98,
          status: 'FAILED',
          evidence: {
            tampered_method: 'Array.prototype.push',
            hook_signature: '0xDEADBEEF_TAMPER'
          }
        });
      }

      latestAuditReport = report;

      // 2. Render Metrics & Detectors immediately from scan report
      renderMetrics(report);
      renderDetectorsList(report.items);
      rawPayloadCode.textContent = JSON.stringify(report, null, 2);

      // 3. Transmit telemetry directly to the single Data Ingest API URL
      const response = await fetch(ingestUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-SecureShield-Tenant': report.tenant_id || 'TEN-WEB-TESTER-01',
          'X-SecureShield-AppId': report.app_id || 'secureshield_web_tester',
          'ngrok-skip-browser-warning': 'true'
        },
        body: JSON.stringify(report)
      });

      const roundtripMs = Math.round(performance.now() - startTime);
      const isSuccess = response.ok;
      const resJson = await response.json().catch(() => ({ status: response.status, statusText: response.statusText }));

      latestServerResponse = resJson;
      rawResponseCode.textContent = JSON.stringify(resJson, null, 2);

      // 4. Update Ingestion Status and Server Card
      if (isSuccess) {
        ingestStatusDisplay.textContent = 'ONLINE (200 OK)';
        ingestStatusDisplay.className = 'metric-value verdict-secure';
        ingestLatencyDisplay.textContent = `Payload ingested in ${roundtripMs}ms`;

        httpStatusChip.textContent = `HTTP ${response.status} OK`;
        httpStatusChip.className = 'status-chip chip-success';

        const action = resJson.decision_action || resJson.decisionAction || resJson.action || 'ALLOW';
        respDecisionAction.textContent = action;
        respDecisionAction.style.color = action === 'BLOCK' ? '#f87171' : action === 'PAUSED' ? '#fbbf24' : '#34d399';
        respLatency.textContent = `${roundtripMs} ms`;
        respMessage.textContent = resJson.message || resJson.reason || 'Telemetry processed & verified by policy engine';
        respMessage.className = 'resp-val';

        showToast(`Telemetry ingested successfully (${roundtripMs}ms)`, 'success');
      } else {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

    } catch (err) {
      const roundtripMs = Math.round(performance.now() - startTime);
      console.warn('[SecureShield Ingest] Ingestion network notice:', err);

      ingestStatusDisplay.textContent = 'OFFLINE / UNREACHABLE';
      ingestStatusDisplay.className = 'metric-value verdict-blocked';
      ingestLatencyDisplay.textContent = `Failed after ${roundtripMs}ms (Check endpoint URL)`;

      httpStatusChip.textContent = 'NETWORK / CORS ERROR';
      httpStatusChip.className = 'status-chip chip-error';

      respDecisionAction.textContent = 'OFFLINE';
      respDecisionAction.style.color = '#f87171';
      respLatency.textContent = `${roundtripMs} ms`;
      respMessage.textContent = `Could not reach ${ingestUrl}. Ensure the SecureShield server is running or check the URL.`;
      respMessage.className = 'resp-val text-muted';

      latestServerResponse = {
        error: err.message,
        target_url: ingestUrl,
        timestamp: new Date().toISOString(),
        tip: 'Ensure the backend server is started at this address with CORS enabled.'
      };
      rawResponseCode.textContent = JSON.stringify(latestServerResponse, null, 2);

      showToast(`Ingest notice: ${err.message}`, 'error');
    }
  }

  // Render Metrics Ribbon
  function renderMetrics(report) {
    if (!report) return;

    // Verdict
    if (report.verdict === 'SECURE') {
      verdictDisplay.textContent = 'SECURE';
      verdictDisplay.className = 'metric-value verdict-secure';
      verdictSub.textContent = `Low risk posture (${report.risk_score}/100)`;
    } else {
      verdictDisplay.textContent = 'BLOCKED / RISK';
      verdictDisplay.className = 'metric-value verdict-blocked';
      verdictSub.textContent = `${report.risk_tier} risk detected (${report.risk_score}/100)`;
    }

    // Trust Score (0 to 100)
    const trustScore = Math.max(0, 100 - (report.risk_score || 0));
    trustScoreDisplay.textContent = trustScore;
    scoreBarFill.style.width = `${trustScore}%`;
    scoreBarFill.style.background = trustScore >= 70 ? 'linear-gradient(90deg, #06b6d4, #10b981)' : trustScore >= 40 ? 'linear-gradient(90deg, #f59e0b, #eab308)' : 'linear-gradient(90deg, #ef4444, #dc2626)';

    // Detector Counts
    const total = report.total_detectors || report.items.length;
    const passed = report.passed !== undefined ? report.passed : report.items.filter(i => !i.triggered).length;
    const failed = report.failed !== undefined ? report.failed : report.items.filter(i => i.triggered).length;

    detectorsCountDisplay.textContent = `${total} Active`;
    detectorsPassedCount.textContent = passed;
    detectorsFailedCount.textContent = failed;
    detectorTabBadge.textContent = total;

    // Device Hash
    if (report.device_id_hash) {
      deviceHashDisplay.textContent = `Device: ${report.device_id_hash}`;
    }
  }

  // Render Detector Grid
  function renderDetectorsList(items) {
    if (!items || !items.length) {
      detectorsList.innerHTML = '<div class="loading-state"><p>No detectors found in report</p></div>';
      return;
    }

    const searchQuery = detectorSearchInput.value.toLowerCase().trim();
    const activeFilter = document.querySelector('.filter-pill.active')?.getAttribute('data-filter') || 'all';

    const filtered = items.filter(item => {
      const name = (item.name || item.id || '').toLowerCase();
      const cat = (item.category || '').toLowerCase();
      const matchesSearch = !searchQuery || name.includes(searchQuery) || cat.includes(searchQuery);

      if (!matchesSearch) return false;

      const isFailed = item.triggered || item.status === 'FAILED';
      if (activeFilter === 'flagged') return isFailed;
      if (activeFilter === 'passed') return !isFailed;
      return true;
    });

    if (!filtered.length) {
      detectorsList.innerHTML = `<div class="loading-state"><p>No detectors match the filter "${searchQuery || activeFilter}"</p></div>`;
      return;
    }

    detectorsList.innerHTML = filtered.map(item => {
      const isFailed = item.triggered || item.status === 'FAILED';
      const statusClass = isFailed ? 'badge-failed' : 'badge-passed';
      const statusText = isFailed ? 'FLAGGED' : 'PASSED';
      const itemClass = isFailed ? 'detector-item-card flagged' : 'detector-item-card';

      return `
        <div class="${itemClass}">
          <div class="detector-item-top">
            <span class="detector-name" title="${item.name || item.id}">${item.name || item.id}</span>
            <span class="detector-badge ${statusClass}">${statusText}</span>
          </div>
          <div class="detector-details">
            <span>Cat: ${item.category || 'INTEGRITY'}</span>
            <span>Conf: ${Math.round((item.confidence || 0.85) * 100)}% &bull; Sev: ${item.severity || 1}</span>
          </div>
        </div>
      `;
    }).join('');
  }

  // Toast Notification Helper
  function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    const icon = type === 'success' ? '✓' : type === 'error' ? '✕' : 'ℹ';
    toast.innerHTML = `<span><strong>${icon}</strong></span><span>${message}</span>`;
    toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 3200);
  }

  // Event Listeners
  dataIngestApiInput.addEventListener('input', () => {
    footerTargetUrl.textContent = dataIngestApiInput.value.trim() || DEFAULT_INGEST_URL;
  });

  resetEndpointBtn.addEventListener('click', () => {
    dataIngestApiInput.value = DEFAULT_INGEST_URL;
    footerTargetUrl.textContent = DEFAULT_INGEST_URL;
    presetChips.forEach(c => c.classList.remove('active'));
    presetChips[0]?.classList.add('active');
    showToast('Reset to default Ingest API URL', 'info');
  });

  presetChips.forEach(chip => {
    chip.addEventListener('click', () => {
      presetChips.forEach(c => c.classList.remove('active'));
      chip.classList.add('active');
      const url = chip.getAttribute('data-url');
      if (url) {
        dataIngestApiInput.value = url;
        footerTargetUrl.textContent = url;
        showToast(`Target URL set: ${url}`, 'info');
      }
    });
  });

  runScanAndIngestBtn.addEventListener('click', () => {
    executeScanAndIngest();
  });

  triggerThreatSimBtn.addEventListener('click', () => {
    simulatedThreatActive = !simulatedThreatActive;
    if (simulatedThreatActive) {
      triggerThreatSimBtn.classList.add('active-pulse');
      triggerThreatSimBtn.querySelector('strong').textContent = 'Simulated Threat: ACTIVE';
      showToast('⚠️ Synthetic Prototype Pollution Threat Injected', 'error');
    } else {
      triggerThreatSimBtn.classList.remove('active-pulse');
      triggerThreatSimBtn.querySelector('strong').textContent = 'Simulate Threat & Ingest';
      showToast('Threat simulation reset to normal', 'info');
    }
    executeScanAndIngest();
  });

  autoIngestToggleBtn.addEventListener('click', () => {
    isAutoIngesting = !isAutoIngesting;
    if (isAutoIngesting) {
      autoIngestToggleBtn.classList.add('active-pulse');
      autoIngestStatusText.textContent = 'Auto-Ingest: ACTIVE (10s)';
      showToast('Continuous 10s Telemetry Ingest Heartbeat Started', 'success');
      autoIngestTimer = setInterval(() => {
        executeScanAndIngest();
      }, 10000);
    } else {
      autoIngestToggleBtn.classList.remove('active-pulse');
      autoIngestStatusText.textContent = 'Auto-Ingest: OFF';
      clearInterval(autoIngestTimer);
      autoIngestTimer = null;
      showToast('Auto-Ingest stopped', 'info');
    }
  });

  refreshPageBtn.addEventListener('click', () => {
    window.location.reload();
  });

  // Tab switching
  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetTab = btn.getAttribute('data-tab');
      tabButtons.forEach(b => b.classList.remove('active'));
      tabPanes.forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      document.getElementById(targetTab)?.classList.add('active');
    });
  });

  // Copy Tab Content
  copyTabContentBtn.addEventListener('click', () => {
    const activeTab = document.querySelector('.tab-pane.active');
    let textToCopy = '';

    if (activeTab?.id === 'detectorsTab') {
      textToCopy = JSON.stringify(latestAuditReport?.items || [], null, 2);
    } else if (activeTab?.id === 'payloadTab') {
      textToCopy = rawPayloadCode.textContent;
    } else if (activeTab?.id === 'responseTab') {
      textToCopy = rawResponseCode.textContent;
    }

    navigator.clipboard.writeText(textToCopy).then(() => {
      showToast('Copied content to clipboard', 'success');
    }).catch(err => {
      showToast('Failed to copy to clipboard', 'error');
    });
  });

  // Detector search & filters
  detectorSearchInput.addEventListener('input', () => {
    if (latestAuditReport) {
      renderDetectorsList(latestAuditReport.items);
    }
  });

  filterPills.forEach(pill => {
    pill.addEventListener('click', () => {
      filterPills.forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      if (latestAuditReport) {
        renderDetectorsList(latestAuditReport.items);
      }
    });
  });

  // Share & Multi-Device handling
  const shareDeviceBtn = document.getElementById('shareDeviceBtn');
  const networkShareBanner = document.getElementById('networkShareBanner');
  const networkUrlDisplay = document.getElementById('networkUrlDisplay');
  const copyShareUrlBtn = document.getElementById('copyShareUrlBtn');

  async function discoverServerInfo() {
    try {
      const res = await fetch('/api/info');
      if (res.ok) {
        const info = await res.json();
        if (info.networkUrl) {
          networkUrlDisplay.textContent = info.networkUrl;
        }
      }
    } catch {
      // Fallback if not running in C# host
      const host = window.location.host || 'localhost:8080';
      networkUrlDisplay.textContent = `${window.location.protocol}//${host}`;
    }
  }

  if (shareDeviceBtn) {
    shareDeviceBtn.addEventListener('click', () => {
      const isHidden = networkShareBanner.style.display === 'none';
      networkShareBanner.style.display = isHidden ? 'block' : 'none';
      if (isHidden) {
        discoverServerInfo();
      }
    });
  }

  if (copyShareUrlBtn) {
    copyShareUrlBtn.addEventListener('click', () => {
      const url = networkUrlDisplay.textContent;
      navigator.clipboard.writeText(url).then(() => {
        showToast(`Copied share URL: ${url}`, 'success');
      });
    });
  }

  // Bootstrap when DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      initSDK();
      discoverServerInfo();
    });
  } else {
    initSDK();
    discoverServerInfo();
  }

})();
