export class DynamicEvalDetector {
    static scan() {
        let triggered = false;
        const evidence = {};
        try {
            const evalStr = Function.prototype.toString.call(window.eval);
            if (!evalStr.includes('[native code]')) {
                triggered = true;
                evidence['eval_hooked'] = evalStr;
            }
        }
        catch (e) {
            evidence['error'] = e.message;
        }
        return {
            id: 'dynamic_eval_detector',
            triggered,
            severity: 3, // HIGH
            category: 'code',
            event: 'dynamic_eval_execution_detected',
            evidence
        };
    }
}
