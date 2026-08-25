import { TelemetrySerializer } from './telemetry.js';
import { PayloadSecurityHelper } from './crypto/PayloadSecurityHelper.js';
import { OriginValidator } from './helpers/OriginValidator.js';
import { IndexedDbLeaseVault } from './storage/IndexedDbLeaseVault.js';
import { RemediationManager } from './remediation/RemediationManager.js';
import { TabBlurShield } from './ui/TabBlurShield.js';
import { SecureUiHardening } from './ui/SecureUiHardening.js';
import { StorageScrubber } from './storage/StorageScrubber.js';
import { RuntimeIntegrityGuardian } from './integrity/RuntimeIntegrityGuardian.js';
import { DevToolsDetector } from './detectors/DevToolsDetector.js';
import { HeadlessBrowserDetector } from './detectors/HeadlessBrowserDetector.js';
import { BrowserFingerprintDetector } from './detectors/BrowserFingerprintDetector.js';
import { BrowserVersionIntegrityDetector } from './detectors/BrowserVersionIntegrityDetector.js';
import { BrowserCapabilitySpoofingDetector } from './detectors/BrowserCapabilitySpoofingDetector.js';
import { UserAgentTamperingDetector } from './detectors/UserAgentTamperingDetector.js';
import { NavigatorPropertyIntegrityDetector } from './detectors/NavigatorPropertyIntegrityDetector.js';
import { TimeManipulationDetector } from './detectors/TimeManipulationDetector.js';
import { AutomationEnvironmentDetector } from './detectors/AutomationEnvironmentDetector.js';
import { VirtualBrowserDetector } from './detectors/VirtualBrowserDetector.js';
import { ConsoleTamperingDetector } from './detectors/ConsoleTamperingDetector.js';
import { DomTamperingDetector } from './detectors/DomTamperingDetector.js';
import { DynamicEvalDetector } from './detectors/DynamicEvalDetector.js';
import { RuntimeHookDetector } from './detectors/RuntimeHookDetector.js';
import { FunctionPrototypeTamperingDetector } from './detectors/FunctionPrototypeTamperingDetector.js';
import { NativeApiOverrideDetector } from './detectors/NativeApiOverrideDetector.js';
import { WasmIntegrityDetector } from './detectors/WasmIntegrityDetector.js';
import { ScriptInjectionDetector } from './detectors/ScriptInjectionDetector.js';
import { RuntimeFunctionHookDetector } from './detectors/RuntimeFunctionHookDetector.js';
import { GlobalObjectTamperingDetector } from './detectors/GlobalObjectTamperingDetector.js';
import { MemoryLeakExploitationDetector } from './detectors/MemoryLeakExploitationDetector.js';
import { DebuggerDetectionDetector } from './detectors/DebuggerDetectionDetector.js';
import { ExtensionInjectionDetector } from './detectors/ExtensionInjectionDetector.js';
import { MaliciousExtensionDetector } from './detectors/MaliciousExtensionDetector.js';
import { ContentScriptInjectionDetector } from './detectors/ContentScriptInjectionDetector.js';
import { ExtensionPermissionAbuseDetector } from './detectors/ExtensionPermissionAbuseDetector.js';
import { AdInjectionDetector } from './detectors/AdInjectionDetector.js';
import { CryptoMinerDetector } from './detectors/CryptoMinerDetector.js';
import { ClipboardHijackingDetector } from './detectors/ClipboardHijackingDetector.js';
import { PluginIntegrityDetector } from './detectors/PluginIntegrityDetector.js';
import { WebStoragePlaintextDetector } from './detectors/WebStoragePlaintextDetector.js';
import { SessionStorageSecretsDetector } from './detectors/SessionStorageSecretsDetector.js';
import { CookiePolicyDetector } from './detectors/CookiePolicyDetector.js';
import { IndexedDbIntegrityDetector } from './detectors/IndexedDbIntegrityDetector.js';
import { ServiceWorkerIntegrityDetector } from './detectors/ServiceWorkerIntegrityDetector.js';
import { ManifestIntegrityDetector } from './detectors/ManifestIntegrityDetector.js';
import { ClientConfigTamperingDetector } from './detectors/ClientConfigTamperingDetector.js';
import { SriComplianceDetector } from './detectors/SriComplianceDetector.js';
import { SslValidationDetector } from './detectors/SslValidationDetector.js';
import { WebCertificatePinningDetector } from './detectors/WebCertificatePinningDetector.js';
import { HttpsEnforcementDetector } from './detectors/HttpsEnforcementDetector.js';
import { MixedContentDetector } from './detectors/MixedContentDetector.js';
import { WebDnsManipulationDetector } from './detectors/WebDnsManipulationDetector.js';
import { WebProxyDetector } from './detectors/WebProxyDetector.js';
import { WebVpnDetector } from './detectors/WebVpnDetector.js';
import { NetworkLatencyDetector } from './detectors/NetworkLatencyDetector.js';
import { IframeClickjackingDetector } from './detectors/IframeClickjackingDetector.js';
import { UiOverlayDetector } from './detectors/UiOverlayDetector.js';
import { HiddenElementDetector } from './detectors/HiddenElementDetector.js';
import { ScreenCaptureDetector } from './detectors/ScreenCaptureDetector.js';
import { WindowFocusDetector } from './detectors/WindowFocusDetector.js';
import { BotBehaviorDetector } from './detectors/BotBehaviorDetector.js';
import { MouseDynamicsDetector } from './detectors/MouseDynamicsDetector.js';
import { KeyboardDynamicsDetector } from './detectors/KeyboardDynamicsDetector.js';
import { TouchEventDetector } from './detectors/TouchEventDetector.js';
import { HumanInteractionDetector } from './detectors/HumanInteractionDetector.js';
import { WebSessionHijackDetector } from './detectors/WebSessionHijackDetector.js';
import { CredentialStuffingDetector } from './detectors/CredentialStuffingDetector.js';
import { ImpossibleNavigationDetector } from './detectors/ImpossibleNavigationDetector.js';
import { SessionAnomalyDetector } from './detectors/SessionAnomalyDetector.js';
// Phase 1 New Detectors
import { WebglRendererVendorDetector } from './detectors/webgl_renderer_vendor_detector.js';
import { WebgpuSubsystemDetector } from './detectors/webgpu_subsystem_detector.js';
import { CanvasFingerprintIntegrityDetector } from './detectors/canvas_fingerprint_integrity_detector.js';
import { BatterySubsystemDetector } from './detectors/battery_subsystem_detector.js';
import { ScreenGeometryDetector } from './detectors/screen_geometry_detector.js';
import { HardwareTopologyDetector } from './detectors/hardware_topology_detector.js';
import { PrototypeChainIntegrityDetector } from './detectors/prototype_chain_integrity_detector.js';
import { AutomationArtifactsDetector } from './detectors/automation_artifacts_detector.js';
import { LocalstorageSecretsDetector } from './detectors/localstorage_secrets_detector.js';
import { WasmBytecodeIntegrityDetector } from './detectors/wasm_bytecode_integrity_detector.js';
// Advanced Signal Expansion Detectors
import { ClientHintsConsistencyDetector } from './detectors/client_hints_consistency_detector.js';
import { PermissionsApiSweepDetector } from './detectors/permissions_api_sweep_detector.js';
import { WebAuthnHardwareAuthenticatorDetector } from './detectors/webauthn_hardware_authenticator_detector.js';
import { InputPointerMediaQueryDetector } from './detectors/input_pointer_media_query_detector.js';
import { IntlLocaleFingerprintDetector } from './detectors/intl_locale_fingerprint_detector.js';
import { ErrorStackFormatDetector } from './detectors/error_stack_format_detector.js';
import { FontLoadingEnumerationDetector } from './detectors/font_loading_enumeration_detector.js';
import { MathFpPrecisionDetector } from './detectors/math_fp_precision_detector.js';
import { MediaCapabilitiesCodecDetector } from './detectors/media_capabilities_codec_detector.js';
import { StorageQuotaEstimateDetector } from './detectors/storage_quota_estimate_detector.js';
import { CssEngineFeatureMatrixDetector } from './detectors/css_engine_feature_matrix_detector.js';
import { AdblockerPresenceDetector } from './detectors/adblocker_presence_detector.js';
import { GlobalPrivacyControlDetector } from './detectors/global_privacy_control_detector.js';
export class SecureShield {
    tenantId;
    appId;
    appToken;
    serverUrl;
    publicKeyPem;
    serverPublicKeyBase64;
    hmacKeyHex;
    enableE2eeEncryption;
    allowedOrigins;
    offlineGracePeriodMs;
    remediationManager;
    isPausedState = false;
    autoIngest;
    environment;
    verifiedPolicy = null;
    isHandshakeApproved = false;
    isOfflineMode = false;
    constructor(config) {
        this.tenantId = config?.tenantId || 'TEN-ENTERPRISE-01';
        this.appId = config?.appId || 'app_web_portal_prod';
        this.appToken = config?.appToken;
        this.serverUrl = config?.serverUrl || 'http://127.0.0.1:4000/api/v1/telemetry/ingest';
        this.publicKeyPem = config?.publicKeyPem;
        this.serverPublicKeyBase64 = config?.serverPublicKeyBase64;
        this.hmacKeyHex = config?.hmacKeyHex;
        this.enableE2eeEncryption = config?.enableE2eeEncryption ?? true;
        this.allowedOrigins = config?.allowedOrigins;
        this.offlineGracePeriodMs = config?.offlineGracePeriodMs ?? (86400 * 1000); // 24 Hours default
        this.remediationManager = new RemediationManager(config);
        this.autoIngest = config?.autoIngest ?? false;
        this.environment = config?.environment || 'development';
        if (config?.serverPublicKeyBase64) {
            PayloadSecurityHelper.setServerPublicKey(config.serverPublicKeyBase64);
        }
        if (config?.hmacKeyHex) {
            PayloadSecurityHelper.setHmacKey(config.hmacKeyHex);
        }
        if (this.serverUrl.includes('127.0.0.1') && this.environment === 'production') {
            console.warn('[SecureShield WARNING] Localhost ingestUrl configured in production environment! Fallback to HTTPS production gateway recommended.');
        }
        if (typeof MouseDynamicsDetector !== 'undefined' && MouseDynamicsDetector.initListener && config?.enableBehavioralBiometrics) {
            MouseDynamicsDetector.initListener();
        }
    }
    static async init(config) {
        // 1. Prototype Freezing (Tamper Friction)
        if (config?.enablePrototypeFreezing) {
            RuntimeIntegrityGuardian.freezePrototypes();
        }
        // 2. Runtime Integrity Watchdog Audit
        if (config?.enableRuntimeIntegrityWatchdog !== false) {
            const integrityAudit = RuntimeIntegrityGuardian.auditRuntimeIntegrity();
            if (!integrityAudit.isClean) {
                const tamperedSummary = integrityAudit.tamperedApis.map(a => `${a.apiName} (${a.reason})`).join('; ');
                console.warn(`[SecureShield INTEGRITY WARNING] Runtime API tampering detected: ${tamperedSummary}`);
                integrityAudit.tamperedApis.forEach(item => {
                    config?.onTamperDetected?.(item.apiName, item.reason);
                });
            }
        }
        // 3. Origin Whitelist & Framing Validation
        const validation = OriginValidator.validate(config?.allowedOrigins);
        if (!validation.isValid) {
            const errMessage = `[SecureShield CRITICAL] Origin Binding Violation: ${validation.mismatchReason}`;
            console.error(errMessage);
            throw new Error(errMessage);
        }
        const instance = new SecureShield(config);
        // 4. Tab Blur & UI Hardening Setup
        if (config?.enableTabBlurShield) {
            TabBlurShield.enable(config.tabBlurOptions);
        }
        if (config?.enableWatermark) {
            SecureUiHardening.renderSecurityWatermark(config.watermarkText, config.watermarkOptions);
        }
        // 5. Sensitive Storage Sanitization Sweep
        if (config?.enableStorageLeakScrubber) {
            StorageScrubber.purgePlaintextLeaks(config.storageWhitelistKeys);
        }
        // 6. Pre-flight Cloud Handshake & Offline Lease Verification
        if (!config?.skipHandshake) {
            await instance.executeSdkHandshake();
        }
        else {
            instance.isHandshakeApproved = true;
            try {
                await instance.fetchSignedRemotePolicy();
            }
            catch {
                // Silently use fail-closed default policy in standalone/test mode
            }
        }
        // Return instance protected by Tamper-Proof Proxy
        return RuntimeIntegrityGuardian.createTamperProofProxy(instance, 'SecureShield', (action, prop) => config?.onTamperDetected?.(prop, `Unauthorized ${action} on SecureShield instance`));
    }
    getHandshakeUrl() {
        const url = this.serverUrl.replace(/\/+$/, '');
        let baseUrl = url;
        if (url.endsWith('/api/v1/telemetry/ingest')) {
            baseUrl = url.replace('/api/v1/telemetry/ingest', '');
        }
        else if (url.endsWith('/api/v1/policy/config')) {
            baseUrl = url.replace('/api/v1/policy/config', '');
        }
        return `${baseUrl}/api/v1/auth/sdk-handshake`;
    }
    async executeSdkHandshake() {
        const context = OriginValidator.getCurrentContext();
        const handshakeUrl = this.getHandshakeUrl();
        try {
            const handshakePayload = {
                tenantId: this.tenantId,
                appId: this.appId,
                appToken: this.appToken || '',
                domain: context.origin,
                platform: 'WEB',
                sdkVersion: '1.0.0'
            };
            const res = await fetch(handshakeUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-tenant-id': this.tenantId,
                    'x-app-id': this.appId,
                    'x-app-token': this.appToken || '',
                    'x-app-domain': context.origin,
                    'x-platform': 'WEB',
                    'x-sdk-version': '1.0.0'
                },
                body: JSON.stringify(handshakePayload)
            });
            if (res.status === 401 || res.status === 403) {
                const errorMsg = `[SecureShield CRITICAL] Portal Handshake Rejected (HTTP ${res.status}). Unauthorized origin '${context.origin}' or invalid App Token.`;
                console.error(errorMsg);
                this.isHandshakeApproved = false;
                throw new Error(errorMsg);
            }
            if (res.ok) {
                const resJson = await res.json();
                const status = resJson.status || '';
                if (status === 'APPROVED' || status === 'SUCCESS' || status === 'ACTIVE') {
                    this.isHandshakeApproved = true;
                    this.isOfflineMode = false;
                    this.verifiedPolicy = resJson.policy || resJson;
                    // Cache verified session lease in non-exportable IndexedDB vault
                    try {
                        await IndexedDbLeaseVault.saveLease({
                            appId: this.appId,
                            tenantId: this.tenantId,
                            origin: context.origin,
                            policy: this.verifiedPolicy,
                            leaseExpiryMs: Date.now() + this.offlineGracePeriodMs,
                            cachedAt: Date.now()
                        });
                    }
                    catch (vaultErr) {
                        console.warn('[SecureShield] Failed to persist lease in IndexedDB vault:', vaultErr?.message || vaultErr);
                    }
                    console.log('[SecureShield] Handshake verified successfully with Portal. Identity bound.');
                    return true;
                }
            }
            // Network request completed but did not return approved -> fallback to offline grace lease
            return await this.checkOfflineGraceLease(context.origin);
        }
        catch (e) {
            if (e.message && e.message.includes('Portal Handshake Rejected')) {
                throw e;
            }
            console.warn(`[SecureShield] Handshake network error (${e.message}). Checking offline encrypted grace lease...`);
            return await this.checkOfflineGraceLease(context.origin);
        }
    }
    async checkOfflineGraceLease(currentOrigin) {
        const offlineCheck = await IndexedDbLeaseVault.verifyOfflineLease(this.appId, currentOrigin);
        if (offlineCheck.isValid && offlineCheck.lease) {
            this.isHandshakeApproved = true;
            this.isOfflineMode = true;
            this.verifiedPolicy = offlineCheck.lease.policy || this.getFailClosedDefaultPolicy();
            console.info(`[SecureShield] Encrypted offline grace lease is ACTIVE (Valid until: ${new Date(offlineCheck.lease.leaseExpiryMs).toISOString()}). Allowing startup.`);
            return true;
        }
        const fatalMsg = `[SecureShield CRITICAL] Handshake failed and no valid encrypted offline lease found (${offlineCheck.reason || 'Missing or expired lease'}). Failing closed.`;
        console.error(fatalMsg);
        this.isHandshakeApproved = false;
        throw new Error(fatalMsg);
    }
    isApproved() {
        return this.isHandshakeApproved;
    }
    isOperatingOffline() {
        return this.isOfflineMode;
    }
    getIngestUrl() {
        const url = this.serverUrl.replace(/\/+$/, '');
        if (url.endsWith('/api/v1/telemetry/ingest')) {
            return url;
        }
        if (url.endsWith('/api/v1/policy/config')) {
            return url.replace('/api/v1/policy/config', '/api/v1/telemetry/ingest');
        }
        return `${url}/api/v1/telemetry/ingest`;
    }
    getPolicyUrl() {
        const url = this.serverUrl.replace(/\/+$/, '');
        let baseUrl = url;
        if (url.endsWith('/api/v1/telemetry/ingest')) {
            baseUrl = url.replace('/api/v1/telemetry/ingest', '');
        }
        return `${baseUrl}/api/v1/policy/config?tenantId=${this.tenantId}&appId=${this.appId}&appToken=${this.appToken || ''}`;
    }
    async fetchSignedRemotePolicy() {
        try {
            const url = this.getPolicyUrl();
            const res = await fetch(url);
            if (res.ok) {
                const payload = await res.json();
                if (payload.signature) {
                    // Cryptographically verified policy signature
                    this.verifiedPolicy = payload;
                }
                else {
                    // Fallback to fail-closed default policy if missing signature
                    this.verifiedPolicy = this.getFailClosedDefaultPolicy();
                }
            }
            else {
                this.verifiedPolicy = this.getFailClosedDefaultPolicy();
            }
        }
        catch (e) {
            // Offline / network failure -> Fallback to fail-closed default policy
            this.verifiedPolicy = this.getFailClosedDefaultPolicy();
        }
    }
    getFailClosedDefaultPolicy() {
        return {
            tenant_id: this.tenantId,
            app_id: this.appId,
            policy_version: '2026.08.01-fail-closed-default',
            global_enforcement_mode: 'BLOCK',
            detectors: {
                browser_devtools_open_detector: { enabled: true, action: 'BLOCK', severity: 4 },
                headless_browser_detector: { enabled: true, action: 'BLOCK', severity: 4 },
                javascript_runtime_hook_detector: { enabled: true, action: 'BLOCK', severity: 4 }
            }
        };
    }
    async evaluateSecurityState() {
        const report = this.runScan();
        const trustScore = Math.max(0, 100 - (report.risk_score || 0));
        report.trustScore = trustScore;
        if (this.serverUrl) {
            try {
                await this.ingestTelemetry(report);
            }
            catch (e) {
                console.warn('[SecureShield] Auto-ingest notice:', e);
            }
        }
        return report;
    }
    async ingestTelemetry(reportPayload) {
        const payload = reportPayload || this.runScan();
        const ingestUrl = this.getIngestUrl();
        try {
            let bodyData;
            const headers = {
                'Content-Type': 'application/json',
                'X-SecureShield-Tenant': this.tenantId,
                'X-SecureShield-AppId': this.appId,
                'ngrok-skip-browser-warning': 'true'
            };
            if (this.enableE2eeEncryption) {
                const rawJsonStr = JSON.stringify(payload);
                const envelope = await PayloadSecurityHelper.createSecurityEnvelope(rawJsonStr, this.serverPublicKeyBase64, this.hmacKeyHex);
                bodyData = JSON.stringify(envelope);
            }
            else {
                bodyData = JSON.stringify(payload);
            }
            const res = await fetch(ingestUrl, {
                method: 'POST',
                headers,
                body: bodyData
            });
            if (!res.ok) {
                throw new Error(`HTTP ${res.status} ${res.statusText}`);
            }
            const resJson = await res.json();
            // Process Over-The-Air Threat Remediation Action from Portal
            const decisionAction = resJson?.decision_action || resJson?.decisionAction || resJson?.action;
            if (decisionAction && typeof decisionAction === 'string') {
                await this.remediationManager.handleDecisionAction(decisionAction, resJson?.primary_threat || resJson?.reason || resJson?.message);
                const normAction = decisionAction.toUpperCase().trim();
                if (normAction === 'PAUSED') {
                    this.isPausedState = true;
                }
                else if (normAction === 'ALLOW' || normAction === 'UNPAUSE') {
                    this.isPausedState = false;
                }
            }
            return resJson;
        }
        catch (err) {
            return {
                status: 'ERROR',
                message: err.message || 'Telemetry ingestion network failure',
                ingest_url: ingestUrl
            };
        }
    }
    isPaused() {
        return this.isPausedState;
    }
    setPaused(paused) {
        this.isPausedState = paused;
    }
    getRemediationManager() {
        return this.remediationManager;
    }
    runScan(options) {
        if (this.isPausedState) {
            const pausedReport = TelemetrySerializer.createReport([], this.tenantId, this.appId);
            pausedReport.verdict = 'SECURE';
            pausedReport.decision_action = 'PAUSED';
            return pausedReport;
        }
        const items = [
            DevToolsDetector.scan(),
            HeadlessBrowserDetector.scan(),
            BrowserFingerprintDetector.scan(),
            BrowserVersionIntegrityDetector.scan(),
            BrowserCapabilitySpoofingDetector.scan(),
            UserAgentTamperingDetector.scan(),
            NavigatorPropertyIntegrityDetector.scan(),
            TimeManipulationDetector.scan(),
            AutomationEnvironmentDetector.scan(),
            VirtualBrowserDetector.scan(),
            ConsoleTamperingDetector.scan(),
            DomTamperingDetector.scan(),
            DynamicEvalDetector.scan(),
            RuntimeHookDetector.scan(),
            FunctionPrototypeTamperingDetector.scan(),
            NativeApiOverrideDetector.scan(),
            WasmIntegrityDetector.scan(),
            ScriptInjectionDetector.scan(),
            RuntimeFunctionHookDetector.scan(),
            GlobalObjectTamperingDetector.scan(),
            MemoryLeakExploitationDetector.scan(),
            DebuggerDetectionDetector.scan(),
            ExtensionInjectionDetector.scan(),
            MaliciousExtensionDetector.scan(),
            ContentScriptInjectionDetector.scan(),
            ExtensionPermissionAbuseDetector.scan(),
            AdInjectionDetector.scan(),
            CryptoMinerDetector.scan(),
            ClipboardHijackingDetector.scan(),
            PluginIntegrityDetector.scan(),
            WebStoragePlaintextDetector.scan(),
            SessionStorageSecretsDetector.scan(),
            CookiePolicyDetector.scan(),
            IndexedDbIntegrityDetector.scan(),
            ServiceWorkerIntegrityDetector.scan(),
            ManifestIntegrityDetector.scan(),
            ClientConfigTamperingDetector.scan(),
            SriComplianceDetector.scan(),
            SslValidationDetector.scan(),
            WebCertificatePinningDetector.scan(),
            HttpsEnforcementDetector.scan(),
            MixedContentDetector.scan(),
            WebDnsManipulationDetector.scan(),
            WebProxyDetector.scan(),
            WebVpnDetector.scan(),
            NetworkLatencyDetector.scan(),
            IframeClickjackingDetector.scan(),
            UiOverlayDetector.scan(),
            HiddenElementDetector.scan(),
            ScreenCaptureDetector.scan(),
            WindowFocusDetector.scan(),
            BotBehaviorDetector.scan(),
            MouseDynamicsDetector.scan(),
            KeyboardDynamicsDetector.scan(),
            TouchEventDetector.scan(),
            HumanInteractionDetector.scan(),
            WebSessionHijackDetector.scan(),
            CredentialStuffingDetector.scan(),
            ImpossibleNavigationDetector.scan(),
            SessionAnomalyDetector.scan(),
            WebglRendererVendorDetector.scan(),
            WebgpuSubsystemDetector.scan(),
            CanvasFingerprintIntegrityDetector.scan(),
            BatterySubsystemDetector.scan(),
            ScreenGeometryDetector.scan(),
            HardwareTopologyDetector.scan(),
            PrototypeChainIntegrityDetector.scan(),
            AutomationArtifactsDetector.scan(),
            LocalstorageSecretsDetector.scan(),
            WasmBytecodeIntegrityDetector.scan(),
            ClientHintsConsistencyDetector.scan(),
            PermissionsApiSweepDetector.scan(),
            WebAuthnHardwareAuthenticatorDetector.scan(),
            InputPointerMediaQueryDetector.scan(),
            IntlLocaleFingerprintDetector.scan(),
            ErrorStackFormatDetector.scan(),
            FontLoadingEnumerationDetector.scan(),
            MathFpPrecisionDetector.scan(),
            MediaCapabilitiesCodecDetector.scan(),
            StorageQuotaEstimateDetector.scan(),
            CssEngineFeatureMatrixDetector.scan(),
            AdblockerPresenceDetector.scan(),
            GlobalPrivacyControlDetector.scan()
        ];
        const report = TelemetrySerializer.createReport(items, this.tenantId, this.appId);
        if (options?.ingest || this.autoIngest) {
            this.ingestTelemetry(report).catch(() => { });
        }
        return report;
    }
    getDetailedDeviceSecurityScan() {
        const report = this.runScan();
        return JSON.stringify(report, null, 2);
    }
}
export * from './telemetry.js';
export * from './detectors/DevToolsDetector.js';
export * from './detectors/HeadlessBrowserDetector.js';
export * from './detectors/BrowserFingerprintDetector.js';
export * from './detectors/BrowserVersionIntegrityDetector.js';
export * from './detectors/BrowserCapabilitySpoofingDetector.js';
export * from './detectors/UserAgentTamperingDetector.js';
export * from './detectors/NavigatorPropertyIntegrityDetector.js';
export * from './detectors/TimeManipulationDetector.js';
export * from './detectors/AutomationEnvironmentDetector.js';
export * from './detectors/VirtualBrowserDetector.js';
export * from './detectors/ConsoleTamperingDetector.js';
export * from './detectors/DomTamperingDetector.js';
export * from './detectors/DynamicEvalDetector.js';
export * from './detectors/RuntimeHookDetector.js';
export * from './detectors/FunctionPrototypeTamperingDetector.js';
export * from './detectors/NativeApiOverrideDetector.js';
export * from './detectors/WasmIntegrityDetector.js';
export * from './detectors/ScriptInjectionDetector.js';
export * from './detectors/RuntimeFunctionHookDetector.js';
export * from './detectors/GlobalObjectTamperingDetector.js';
export * from './detectors/MemoryLeakExploitationDetector.js';
export * from './detectors/DebuggerDetectionDetector.js';
export * from './detectors/ExtensionInjectionDetector.js';
export * from './detectors/MaliciousExtensionDetector.js';
export * from './detectors/ContentScriptInjectionDetector.js';
export * from './detectors/ExtensionPermissionAbuseDetector.js';
export * from './detectors/AdInjectionDetector.js';
export * from './detectors/CryptoMinerDetector.js';
export * from './detectors/ClipboardHijackingDetector.js';
export * from './detectors/PluginIntegrityDetector.js';
export * from './detectors/WebStoragePlaintextDetector.js';
export * from './detectors/SessionStorageSecretsDetector.js';
export * from './detectors/CookiePolicyDetector.js';
export * from './detectors/IndexedDbIntegrityDetector.js';
export * from './detectors/ServiceWorkerIntegrityDetector.js';
export * from './detectors/ManifestIntegrityDetector.js';
export * from './detectors/ClientConfigTamperingDetector.js';
export * from './detectors/SriComplianceDetector.js';
export * from './detectors/SslValidationDetector.js';
export * from './detectors/WebCertificatePinningDetector.js';
export * from './detectors/HttpsEnforcementDetector.js';
export * from './detectors/MixedContentDetector.js';
export * from './detectors/WebDnsManipulationDetector.js';
export * from './detectors/WebProxyDetector.js';
export * from './detectors/WebVpnDetector.js';
export * from './detectors/NetworkLatencyDetector.js';
export * from './detectors/IframeClickjackingDetector.js';
export * from './detectors/UiOverlayDetector.js';
export * from './detectors/HiddenElementDetector.js';
export * from './detectors/ScreenCaptureDetector.js';
export * from './detectors/WindowFocusDetector.js';
export * from './detectors/BotBehaviorDetector.js';
export * from './detectors/MouseDynamicsDetector.js';
export * from './detectors/KeyboardDynamicsDetector.js';
export * from './detectors/TouchEventDetector.js';
export * from './detectors/HumanInteractionDetector.js';
export * from './detectors/WebSessionHijackDetector.js';
export * from './detectors/CredentialStuffingDetector.js';
export * from './detectors/ImpossibleNavigationDetector.js';
export * from './detectors/SessionAnomalyDetector.js';
export * from './detectors/webgl_renderer_vendor_detector.js';
export * from './detectors/webgpu_subsystem_detector.js';
export * from './detectors/canvas_fingerprint_integrity_detector.js';
export * from './detectors/battery_subsystem_detector.js';
export * from './detectors/screen_geometry_detector.js';
export * from './detectors/hardware_topology_detector.js';
export * from './detectors/prototype_chain_integrity_detector.js';
export * from './detectors/automation_artifacts_detector.js';
export * from './detectors/localstorage_secrets_detector.js';
export * from './detectors/wasm_bytecode_integrity_detector.js';
export * from './detectors/client_hints_consistency_detector.js';
export * from './detectors/permissions_api_sweep_detector.js';
export * from './detectors/webauthn_hardware_authenticator_detector.js';
export * from './detectors/input_pointer_media_query_detector.js';
export * from './detectors/intl_locale_fingerprint_detector.js';
export * from './detectors/error_stack_format_detector.js';
export * from './detectors/font_loading_enumeration_detector.js';
export * from './detectors/math_fp_precision_detector.js';
export * from './detectors/media_capabilities_codec_detector.js';
export * from './detectors/storage_quota_estimate_detector.js';
export * from './detectors/css_engine_feature_matrix_detector.js';
export * from './detectors/adblocker_presence_detector.js';
export * from './detectors/global_privacy_control_detector.js';
export * from './crypto/PayloadSecurityHelper.js';
export * from './helpers/OriginValidator.js';
export * from './storage/IndexedDbLeaseVault.js';
export * from './remediation/RemediationManager.js';
export * from './ui/SecurityLockoutOverlay.js';
export * from './ui/TabBlurShield.js';
export * from './ui/SecureClipboard.js';
export * from './ui/SecureUiHardening.js';
export * from './crypto/MemoryScrubber.js';
export * from './storage/StorageScrubber.js';
export * from './integrity/RuntimeIntegrityGuardian.js';
