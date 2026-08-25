export class CryptoMinerDetector {
    static scan() {
        const nowMs = Date.now().toString();
        const evidence = {
            "scan_timestamp_ms": nowMs,
            "probe_target": "DOM Script Nodes & Web Worker Threads",
            "probe_technique": "crypto_miner_script_signature_audit",
            "expected_value": "No in-browser cryptocurrency mining scripts loaded",
            "threat_classification": "Unauthorized In-Browser Crypto Miner Script (Coinhive / Crypto-Loot)",
            "remediation_guidance": "Terminate web worker threads and remove unauthorized mining scripts"
        };
        let triggered = false;
        let actualVal = "No crypto miner signatures detected in DOM scripts";
        try {
            const scripts = Array.from(document.querySelectorAll("script"));
            for (const s of scripts) {
                const src = s.src.toLowerCase();
                const content = s.textContent?.toLowerCase() || "";
                if (src.includes("coinhive") || src.includes("crypto-loot") || src.includes("mineralt") ||
                    content.includes("coinhive.anonymous") || content.includes("miner.start()")) {
                    triggered = true;
                    actualVal = `Detected miner script: ${src || "inline script"}`;
                    break;
                }
            }
        }
        catch (e) {
            actualVal = `Miner audit error: ${e.message}`;
        }
        evidence["actual_value"] = actualVal;
        if (!triggered) {
            evidence["remediation_guidance"] = "No action required. DOM script tree clean.";
        }
        return {
            id: "crypto_miner_injection_detector",
            triggered,
            severity: triggered ? 4 : 0,
            category: "extension_security",
            event: triggered ? "crypto_miner_detected" : "crypto_miner_clean",
            evidence
        };
    }
}
