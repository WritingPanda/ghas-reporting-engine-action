import { Report } from './reports';

export interface MarkdownOptions {
  includeEmpty?: boolean;
  owner?: string;
  repo?: string;
  includeAlertDetails?: boolean; // default true
}

export function buildMarkdownSummary(reports: Report[], opts: MarkdownOptions = {}): string {
  const includeEmpty = opts.includeEmpty !== false; // default true
  const includeAlertDetails = opts.includeAlertDetails !== false; // default true
  const owner = opts.owner || process.env.GITHUB_REPOSITORY?.split('/')?.[0] || 'unknown-owner';
  const repo = opts.repo || process.env.GITHUB_REPOSITORY?.split('/')?.[1] || 'unknown-repo';
  const fwReports = reports.filter(r => r.type !== 'summary');
  const lines: string[] = [];
  lines.push('# GHAS Framework Coverage Summary');
  lines.push('');
  const header = ['Framework', 'Matched Alerts', 'Matched CWEs', 'Framework CWE Total', 'CWE Coverage %', 'High', 'Medium', 'Low', 'Other'];
  lines.push(`| ${header.join(' | ')} |`);
  lines.push(`| ${header.map(() => '-').join(' | ')} |`);
  for (const r of fwReports) {
    if (!includeEmpty && (r.matchedAlerts || 0) === 0) continue;
    const high = r.severityBreakdown?.high || 0;
    const med = r.severityBreakdown?.medium || 0;
    const low = r.severityBreakdown?.low || 0;
    const other = Object.entries(r.severityBreakdown || {})
      .filter(([k]) => !['high', 'medium', 'low'].includes(k))
      .reduce((a, [, v]) => a + (v as number), 0);
    const coverage = r.totalFrameworkCWEs ? ((r.matchedCWEs || 0) / r.totalFrameworkCWEs * 100).toFixed(1) : '0.0';
    lines.push(`| ${r.type} | ${r.matchedAlerts || 0} | ${r.matchedCWEs || 0} | ${r.totalFrameworkCWEs || 0} | ${coverage} | ${high} | ${med} | ${low} | ${other} |`);
  }
  lines.push('');
  lines.push('## Notes');
  lines.push('- CWE Coverage % = Matched CWEs / Total CWEs defined for framework * 100');
  lines.push('- Other severities aggregate any non-high/medium/low severities');

  if (includeAlertDetails) {
    const summary = reports.find(r => r.type === 'summary');
    if (summary) {
      lines.push('');
      lines.push('## Alerts Grouped by CWE');
      // Build grouping map CWE -> alerts
      interface AlertRow { id: any; ruleId: string; severity: string; cwes: string[]; source?: string; ghsaId?: string; cveIds?: string[] }
      const rows: AlertRow[] = (summary.findings || []).map((f: any) => ({
        id: f.id,
        ruleId: f.ruleId || 'unknown-rule',
        severity: f.severity || 'unknown',
        cwes: Array.isArray(f.cwes) ? f.cwes : [],
        source: f.source,
        ghsaId: f.ghsaId,
        cveIds: f.cveIds
      }));
      // Enrich GHSA / CVE from ruleId if missing
      for (const r of rows) {
        if (!r.ghsaId) {
          const m = /GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/i.exec(r.ruleId);
          if (m) r.ghsaId = m[0].toUpperCase();
        }
        if (!r.cveIds || r.cveIds.length === 0) {
          const cves = new Set<string>();
          const re = /CVE-\d{4}-\d{4,7}/gi;
          let m: RegExpExecArray | null;
          while ((m = re.exec(r.ruleId)) !== null) cves.add(m[0].toUpperCase());
          if (cves.size) r.cveIds = Array.from(cves).sort();
        }
      }
      const cweMap: Record<string, AlertRow[]> = {};
      for (const r of rows) {
        if (!r.cwes.length) {
          cweMap['(NO-CWE)'] = cweMap['(NO-CWE)'] || [];
          cweMap['(NO-CWE)'].push(r);
        } else {
          for (const c of r.cwes) {
            cweMap[c] = cweMap[c] || [];
            cweMap[c].push(r);
          }
        }
      }
      const sortedCWEs = Object.keys(cweMap).sort((a, b) => {
        const diff = cweMap[b].length - cweMap[a].length;
        if (diff !== 0) return diff;
        return a.localeCompare(b);
      });
      for (const cwe of sortedCWEs) {
        const list = cweMap[cwe];
        lines.push('');
        lines.push(`### ${cwe} (${list.length} alert${list.length === 1 ? '' : 's'})`);
        lines.push('');
        lines.push('| Alert | Tool | Severity | GHSA | CVEs | Repository | URL |');
        lines.push('| - | - | - | - | - | - | - |');
        for (const a of list) {
          const source = a.source || inferSource(a.ruleId) || 'code-scanning';
          const url = buildAlertURL(owner, repo, source, a.id);
          const escapedRule = escapePipes(a.ruleId);
          const ghsa = a.ghsaId ? `[${a.ghsaId}](https://github.com/advisories/${a.ghsaId})` : '';
          const cves = (a.cveIds || []).map((c: string) => `[${c}](https://nvd.nist.gov/vuln/detail/${c})`).join(', ');
          const toolLabel = toToolLabel(source, a.ruleId);
          lines.push(`| ${escapedRule} | ${toolLabel} | ${a.severity} | ${ghsa} | ${cves} | ${owner}/${repo} | ${url} |`);
        }
      }
    }
  }
  // Dependabot CVE -> CWE alignment summary
  const summary = reports.find(r => r.type === 'summary');
  if (summary) {
    const dependabotRows = (summary.findings || []).filter((f: any) => f.source === 'dependabot');
    const map: Record<string, { ghsa?: string; cwes: Set<string> }> = {};
    for (const row of dependabotRows) {
      const ghsa = row.ghsaId;
      const cwes: string[] = Array.isArray(row.cwes) ? row.cwes : [];
      const cveIds: string[] = Array.isArray(row.cveIds) ? row.cveIds : [];
      for (const cve of cveIds) {
        if (!map[cve]) map[cve] = { ghsa: ghsa, cwes: new Set<string>() };
        cwes.forEach(c => map[cve].cwes.add(c));
        // Prefer GHSA if present
        if (ghsa) map[cve].ghsa = ghsa;
      }
    }
    const cveKeys = Object.keys(map).sort();
    if (cveKeys.length) {
      lines.push('');
      lines.push('## Dependabot CVE to CWE Mapping');
      lines.push('');
      lines.push('| CVE | GHSA | CWEs | Tool |');
      lines.push('| - | - | - | - |');
      for (const cve of cveKeys) {
        const entry = map[cve];
        const ghsaLink = entry.ghsa ? `[${entry.ghsa}](https://github.com/advisories/${entry.ghsa})` : '';
        const cweList = Array.from(entry.cwes).sort().join(', ');
        lines.push(`| [${cve}](https://nvd.nist.gov/vuln/detail/${cve}) | ${ghsaLink} | ${cweList} | Dependabot |`);
      }
    }
  }
  return lines.join('\n');
}

function buildAlertURL(owner: string, repo: string, source: string, id: any): string {
  if (!id && id !== 0) return '';
  switch (source) {
    case 'dependabot':
      return `https://github.com/${owner}/${repo}/security/dependabot/${id}`;
    case 'secret-scanning':
      return `https://github.com/${owner}/${repo}/security/secret-scanning/${id}`;
    default:
      return `https://github.com/${owner}/${repo}/security/code-scanning/${id}`;
  }
}

function inferSource(ruleId: string): string | undefined {
  if (!ruleId) return undefined;
  // Heuristic: Dependabot advisories often start with GHSA-
  if (/^ghsa-/i.test(ruleId)) return 'dependabot';
  return undefined; // default handled by caller
}

function toToolLabel(source: string, ruleId?: string): string {
  switch (source) {
    case 'dependabot': return 'Dependabot';
    case 'secret-scanning': return 'Secret Protection';
    case 'code-scanning':
    default:
      // If ruleId hints at actions/* or other provider, still show Code Scanning
      return 'CodeQL';
  }
}

function escapePipes(text: string): string {
  return text.replace(/\|/g, '\\|');
}
