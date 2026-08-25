export class DomTamperingDetector {
    static scan() {
        let triggered = false;
        const evidence = {};
        try {
            const formInputs = document.querySelectorAll('input[type="password"], input[type="credit-card"]');
            formInputs.forEach((input) => {
                const el = input;
                if (el.getAttribute('autocomplete') === 'off' && el.dataset.tampered === 'true') {
                    triggered = true;
                    evidence['input_tampered'] = el.name || el.id;
                }
            });
        }
        catch (e) {
            evidence['error'] = e.message;
        }
        return {
            id: 'dom_tampering_detector',
            triggered,
            severity: 2, // MEDIUM
            category: 'ui',
            event: 'dom_input_field_tampered',
            evidence
        };
    }
}
