import { describe, it, expect } from 'vitest';
import { buildReports } from '../reports';

describe('buildReports', () => {
  it('produces reports with CWE mapping and summary', async () => {
    const alerts = [
      { id: 1, rule: { id: 'R1', severity: 'high', cwe: 'CWE-79' } },
      // CWE via tags lowercase external pattern
      { id: 2, rule: { id: 'R2', severity: 'low', cwe: [], tags: ['security', 'external/cwe/cwe-89', 'external/cwe/cwe-20'] } },
      // Rule with no explicit CWE but known mapping
      { id: 3, rule: { id: 'java/xss', severity: 'medium' } }
    ];
    const frameworks = ['owasp'];
    const reports = await buildReports({ alerts, frameworks });
    const owasp = reports.find(r => r.type === 'owasp');
    expect(owasp).toBeTruthy();
    expect(owasp?.matchedAlerts).toBeGreaterThan(0);
    const summary = reports.find(r => r.type === 'summary');
    expect(summary?.totalAlerts).toBe(3);
    expect(Object.values(summary?.severityBreakdown || {}).reduce((a, b) => a + b, 0)).toBe(3);
    // Ensure CWEs normalized
    const owaspFinding = owasp?.findings.flatMap((f: any) => f.cwes);
    expect(owaspFinding).toContain('CWE-79');
    expect(owaspFinding).toContain('CWE-89');
    expect(owaspFinding).toContain('CWE-20');
    // supplemental mapping produced CWE-79 for java/xss even without explicit CWE
    const xssEntry = owasp?.findings.find((f: any) => f.ruleId === 'java/xss');
    expect(xssEntry.cwes).toContain('CWE-79');
  });

  it('maps dependabot advisory and nested vulnerability CWEs', async () => {
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
    const reports = await buildReports({ alerts: [dependabotAlert, dependabotAlertNested], frameworks: ['owasp'] });
    const owasp = reports.find(r => r.type === 'owasp');
    const cwes = new Set(owasp?.findings.flatMap((f: any) => f.cwes));
    expect(cwes.has('CWE-79')).toBe(true);
    expect(cwes.has('CWE-89')).toBe(true);
  });
});
