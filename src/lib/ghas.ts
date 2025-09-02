import { Octokit } from 'octokit';

export interface FetchAlertsParams {
  token: string;
  owner: string;
  repo: string;
  since?: string;
  until?: string;
  includeDependabot?: boolean;
}

export interface Alert {
  id: number | string;
  rule?: { id?: string; severity?: string; cwe?: string | string[] };
  created_at?: string;
  updated_at?: string;
  [k: string]: any;
}

export async function fetchAlerts({ token, owner, repo, since, until, includeDependabot = true }: FetchAlertsParams): Promise<Alert[]> {
  const octokit = new Octokit({ auth: token });
  const alerts: Alert[] = [];
  // Fetch code scanning alerts
  let page = 1;
  while (true) {
    const res = await octokit.request('GET /repos/{owner}/{repo}/code-scanning/alerts', {
      owner,
      repo,
      per_page: 100,
      page
    });
    const data = res.data as any[];
    if (!data.length) break;
    for (const a of data) {
      const created = a.created_at;
      if (since && created && created < since) continue;
      if (until && created && created > until) continue;
      // Provide a stable id and keep original structure
      alerts.push({
        id: a.number || a.id || `${a.rule?.id}-${a.created_at}`,
        ...a
      });
    }
    if (data.length < 100) break;
    page++;
  }

  if (includeDependabot) {
    // Fetch dependabot alerts (a.k.a. dependency alerts)
    let depPage = 1;
    while (true) {
      const res = await octokit.request('GET /repos/{owner}/{repo}/dependabot/alerts', {
        owner,
        repo,
        per_page: 100,
        page: depPage,
        // potential extra query params could be added (state, ecosystem, package)
      });
      const data = res.data as any[];
      if (!data.length) break;
      for (const a of data) {
        const created = a.created_at || a.updated_at;
        if (since && created && created < since) continue;
        if (until && created && created > until) continue;
        // Extract CWE list from advisory if available
        let cwes: string[] = [];
        const advisory = a.security_advisory || {};
        if (Array.isArray(advisory.cwes)) {
          cwes = advisory.cwes.map((c: any) => c.cwe_id || c).filter(Boolean);
        }
        // Attempt enrichment from advisory.vulnerabilities[].cwes (GitHub may include CVE-linked info)
        if (Array.isArray(advisory.vulnerabilities)) {
          for (const v of advisory.vulnerabilities) {
            if (Array.isArray(v.cwes)) {
              v.cwes.forEach((vc: any) => {
                const id = vc.cwe_id || vc;
                if (id && !cwes.includes(id)) cwes.push(id);
              });
            }
          }
        }
        // Normalize format to CWE-### if numeric
        cwes = cwes.map(id => {
          const m = /^(?:CWE[-_:\s]?)(\d{1,4})$/i.exec(id) || /^(\d{1,4})$/.exec(id);
          if (m) return `CWE-${parseInt(m[1], 10)}`; else return id;
        });
        alerts.push({
          id: a.id,
          rule: {
            id: a.dependency?.package?.name || advisory.ghsa_id || `dependabot-${a.id}`,
            severity: advisory.cvss?.severity?.toLowerCase?.() || advisory.severity || 'unknown',
            cwe: cwes
          },
          created_at: created,
          updated_at: a.updated_at,
          source: 'dependabot',
          ...a
        });
      }
      if (data.length < 100) break;
      depPage++;
    }
  }

  // Fetch secret scanning alerts
  page = 1;
  while (true) {
    const res = await octokit.request('GET /repos/{owner}/{repo}/secret-scanning/alerts', {
      owner,
      repo,
      per_page: 100,
      page
    });
    const data = res.data as any[];
    if (!data.length) break;
    for (const a of data) {
      const created = a.created_at;
      if (since && created && created < since) continue;
      if (until && created && created > until) continue;
      // Map secret scanning alert to Alert shape
      alerts.push({
        id: a.id,
        rule: {
          id: a.secret_type || a.secret_type_display_name,
          severity: a.resolution || 'unknown',
          cwe: a.cwe || ''
        },
        created_at: a.created_at,
        updated_at: a.updated_at,
        source: 'secret-scanning',
        ...a
      });
    }
    if (data.length < 100) break;
    page++;
  }
  return alerts;
}
