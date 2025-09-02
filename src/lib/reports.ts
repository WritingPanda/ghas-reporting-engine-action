
import { Alert } from './ghas';
import { loadFrameworks, matchFrameworks, extractAlertCWEs } from './frameworks';

export interface Report {
  type: string; // framework id or 'summary'
  generatedAt: string;
  totalAlerts: number;
  matchedAlerts?: number;
  matchedCWEs?: number;
  totalFrameworkCWEs?: number;
  severityBreakdown?: { [severity: string]: number };
  findings: any[];
  unmatchedFrameworkCWEs?: string[];
}

export interface BuildReportsParams {
  alerts: Alert[];
  frameworks: string[];
}

// (legacy placeholder removed)

export async function buildReports({ alerts, frameworks }: BuildReportsParams): Promise<Report[]> {
  const now = new Date().toISOString();
  const fwData = loadFrameworks(frameworks);
  const match = matchFrameworks(alerts, fwData);

  // Precompute severities per alert
  const alertSeverity = (a: Alert) => (a.rule?.severity || 'unknown').toLowerCase();

  const reports: Report[] = [];
  for (const fw of fwData) {
    const res = match[fw.id];
    const findings = alerts
      .filter(a => res.matchedAlerts.has(a.id))
      .map(a => ({
        alertId: a.id,
        ruleId: a.rule?.id,
        severity: alertSeverity(a),
        cwes: extractAlertCWEs(a).filter(c => fw.cwes.has(c))
      }));
    const severityBreakdown: { [severity: string]: number } = {};
    for (const f of findings) {
      severityBreakdown[f.severity] = (severityBreakdown[f.severity] || 0) + 1;
    }
    reports.push({
      type: fw.id,
      generatedAt: now,
      totalAlerts: alerts.length,
      matchedAlerts: res.matchedAlerts.size,
      matchedCWEs: res.matchedCWEs.size,
      totalFrameworkCWEs: fw.cwes.size,
      severityBreakdown,
      findings,
      unmatchedFrameworkCWEs: Array.from([...fw.cwes].filter(c => !res.matchedCWEs.has(c))).sort()
    });
  }

  // Summary report
  const allSev: { [severity: string]: number } = {};
  alerts.forEach(a => { const s = alertSeverity(a); allSev[s] = (allSev[s] || 0) + 1; });
  reports.push({
    type: 'summary',
    generatedAt: now,
    totalAlerts: alerts.length,
    severityBreakdown: allSev,
    findings: alerts.map(a => ({
      id: a.id,
      ruleId: a.rule?.id,
      severity: alertSeverity(a),
      cwes: extractAlertCWEs(a),
      source: (a as any).source,
      ghsaId: (a as any).security_advisory?.ghsa_id,
      cveIds: extractCveIds((a as any).security_advisory)
    }))
  });
  return reports;
}

function extractCveIds(advisory: any): string[] | undefined {
  if (!advisory) return undefined;
  const set = new Set<string>();
  const pushMatches = (val: any) => {
    if (!val) return;
    const str = typeof val === 'string' ? val : JSON.stringify(val);
    const re = /CVE-\d{4}-\d{4,7}/gi;
    let m: RegExpExecArray | null;
    while ((m = re.exec(str)) !== null) set.add(m[0].toUpperCase());
  };
  // Common places
  if (advisory.cve_id) pushMatches(advisory.cve_id);
  if (Array.isArray(advisory.identifiers)) advisory.identifiers.forEach(pushMatches);
  pushMatches(advisory.summary);
  pushMatches(advisory.description);
  if (!set.size) return undefined;
  return Array.from(set).sort();
}
