"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const vitest_1 = require("vitest");
const reports_1 = require("../reports");
(0, vitest_1.describe)('buildReports', () => {
    (0, vitest_1.it)('produces reports with CWE mapping and summary', async () => {
        const alerts = [
            { id: 1, rule: { id: 'R1', severity: 'high', cwe: 'CWE-79' } },
            // CWE via tags lowercase external pattern
            { id: 2, rule: { id: 'R2', severity: 'low', cwe: [], tags: ['security', 'external/cwe/cwe-89', 'external/cwe/cwe-20'] } },
            // Rule with no explicit CWE but known mapping
            { id: 3, rule: { id: 'java/xss', severity: 'medium' } }
        ];
        const frameworks = ['owasp'];
        const reports = await (0, reports_1.buildReports)({ alerts, frameworks });
        const owasp = reports.find(r => r.type === 'owasp');
        (0, vitest_1.expect)(owasp).toBeTruthy();
        (0, vitest_1.expect)(owasp?.matchedAlerts).toBeGreaterThan(0);
        const summary = reports.find(r => r.type === 'summary');
        (0, vitest_1.expect)(summary?.totalAlerts).toBe(3);
        (0, vitest_1.expect)(Object.values(summary?.severityBreakdown || {}).reduce((a, b) => a + b, 0)).toBe(3);
        // Ensure CWEs normalized
        const owaspFinding = owasp?.findings.flatMap((f) => f.cwes);
        (0, vitest_1.expect)(owaspFinding).toContain('CWE-79');
        (0, vitest_1.expect)(owaspFinding).toContain('CWE-89');
        (0, vitest_1.expect)(owaspFinding).toContain('CWE-20');
        // supplemental mapping produced CWE-79 for java/xss even without explicit CWE
        const xssEntry = owasp?.findings.find((f) => f.ruleId === 'java/xss');
        (0, vitest_1.expect)(xssEntry.cwes).toContain('CWE-79');
    });
    (0, vitest_1.it)('maps dependabot advisory and nested vulnerability CWEs', async () => {
        const dependabotAlert = {
            id: 'dep1',
            rule: {
                id: 'lodash',
                severity: 'high',
                cwe: ['CWE-79'] // from advisory.cwes
            },
            source: 'dependabot'
        };
        const dependabotAlertNested = {
            id: 'dep2',
            rule: {
                id: 'express',
                severity: 'medium',
                // simulate nested vulnerability cwes normalization (raw numeric and variant)
                cwe: ['79', 'cwe_89']
            },
            source: 'dependabot'
        };
        const reports = await (0, reports_1.buildReports)({ alerts: [dependabotAlert, dependabotAlertNested], frameworks: ['owasp'] });
        const owasp = reports.find(r => r.type === 'owasp');
        const cwes = new Set(owasp?.findings.flatMap((f) => f.cwes));
        (0, vitest_1.expect)(cwes.has('CWE-79')).toBe(true);
        (0, vitest_1.expect)(cwes.has('CWE-89')).toBe(true);
    });
});
