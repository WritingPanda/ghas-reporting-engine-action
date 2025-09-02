"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.buildReports = buildReports;
const frameworks_1 = require("./frameworks");
// (legacy placeholder removed)
async function buildReports({ alerts, frameworks }) {
    const now = new Date().toISOString();
    const fwData = (0, frameworks_1.loadFrameworks)(frameworks);
    const match = (0, frameworks_1.matchFrameworks)(alerts, fwData);
    // Precompute severities per alert
    const alertSeverity = (a) => (a.rule?.severity || 'unknown').toLowerCase();
    const reports = [];
    for (const fw of fwData) {
        const res = match[fw.id];
        const findings = alerts
            .filter(a => res.matchedAlerts.has(a.id))
            .map(a => ({
            alertId: a.id,
            ruleId: a.rule?.id,
            severity: alertSeverity(a),
            cwes: (0, frameworks_1.extractAlertCWEs)(a).filter(c => fw.cwes.has(c))
        }));
        const severityBreakdown = {};
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
    const allSev = {};
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
            cwes: (0, frameworks_1.extractAlertCWEs)(a),
            source: a.source,
            ghsaId: a.security_advisory?.ghsa_id,
            cveIds: extractCveIds(a.security_advisory)
        }))
    });
    return reports;
}
function extractCveIds(advisory) {
    if (!advisory)
        return undefined;
    const set = new Set();
    const pushMatches = (val) => {
        if (!val)
            return;
        const str = typeof val === 'string' ? val : JSON.stringify(val);
        const re = /CVE-\d{4}-\d{4,7}/gi;
        let m;
        while ((m = re.exec(str)) !== null)
            set.add(m[0].toUpperCase());
    };
    // Common places
    if (advisory.cve_id)
        pushMatches(advisory.cve_id);
    if (Array.isArray(advisory.identifiers))
        advisory.identifiers.forEach(pushMatches);
    pushMatches(advisory.summary);
    pushMatches(advisory.description);
    if (!set.size)
        return undefined;
    return Array.from(set).sort();
}
